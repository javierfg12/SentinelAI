"""Explainable sliding-window correlation rules for authentication events."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pandas as pd

from sentinelai.catalog import RULES

SEVERITY_ORDER = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}
SCORES = {"AUTH-001": 82, "AUTH-002": 80, "AUTH-003": 88, "AUTH-004": 95, "AUTH-005": 30}
DOWNGRADED_SCORE = 65  # rule fired with a lower severity than its catalog maximum
ALERT_COLUMNS = (
    "alert_id", "rule_id", "title", "severity", "score", "timestamp", "source_ip", "username",
    "accounts", "description", "mitre_id", "mitre_name", "recommendation", "evidence_count", "evidence_ids",
)
MULTIPLE_ACCOUNTS = ""  # username of alerts that span several accounts; see the "accounts" column


@dataclass(frozen=True)
class DetectionConfig:
    window_minutes: int = 10
    cooldown_minutes: int = 20
    failed_ip_threshold: int = 8
    failed_account_threshold: int = 5
    spraying_users_threshold: int = 6
    success_after_failures: int = 3
    detect_offhours: bool = False
    timezone: str = "Europe/Madrid"
    spraying_max_per_account: int = 2  # AUTH-003 only fires if no account exceeds this many failures

    def validate(self) -> None:
        for field in ("window_minutes", "cooldown_minutes", "failed_ip_threshold", "failed_account_threshold", "spraying_users_threshold", "success_after_failures", "spraying_max_per_account"):
            if getattr(self, field) < 1:
                raise ValueError(f"{field} debe ser positivo")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Zona horaria no reconocida") from exc


def _alert(rule_id: str, occurred: pd.Timestamp, evidence: list, source_ip: str, username: str, detail: str,
           severity: str | None = None) -> dict:
    rule = RULES[rule_id]
    severity = severity or rule["severity"]
    evidences = [x["event_id"] for x in evidence]
    seed = f"{rule_id}:{occurred.isoformat()}:{source_ip}:{username}:{','.join(evidences)}"
    return {
        "alert_id": hashlib.sha256(seed.encode()).hexdigest()[:10].upper(),
        "rule_id": rule_id,
        "title": rule["title"],
        "severity": severity,
        "score": SCORES[rule_id] if severity == rule["severity"] else DOWNGRADED_SCORE,
        "timestamp": occurred.isoformat(),
        "source_ip": source_ip,
        "username": username,
        "accounts": sorted({x["username"] for x in evidence})[:20],
        "description": detail,
        "mitre_id": rule["technique"],
        "mitre_name": rule["technique_name"],
        "recommendation": rule["recommendation"],
        "evidence_count": len(evidences),
        "evidence_ids": evidences[-30:],  # preserve a bounded sample if very large
    }


def detect(events: pd.DataFrame, config: DetectionConfig | None = None) -> pd.DataFrame:
    """Correlate ordered successful/failed authentications without side effects.

    Independent rules can alert on the same events. Detection is intentionally
    heuristic, not proof of attack, and thresholds require environment tuning.
    """
    config = config or DetectionConfig()
    config.validate()
    columns = (
        "event_id", "timestamp", "source_ip", "username", "outcome"
    )
    if not set(columns).issubset(events.columns):
        raise ValueError("Faltan columnas normalizadas para la detección")
    if events.empty:
        return pd.DataFrame(columns=list(ALERT_COLUMNS))

    ordered = events.sort_values(["timestamp", "event_id"])
    window = timedelta(minutes=config.window_minutes)
    cooldown = timedelta(minutes=config.cooldown_minutes)
    result: list[dict] = []

    # One pass builds every bucket: avoids per-group DataFrame work (O(n) overall).
    records = [
        {"event_id": e, "timestamp": t, "source_ip": ip, "username": u, "outcome": o}
        for e, t, ip, u, o in zip(
            ordered["event_id"], ordered["timestamp"].tolist(), ordered["source_ip"],
            ordered["username"], ordered["outcome"],
            strict=True,
        )
    ]
    fail_by_ip: dict[str, list] = defaultdict(list)
    fail_by_pair: dict[tuple, list] = defaultdict(list)
    all_by_pair: dict[tuple, list] = defaultdict(list)
    for e in records:
        pair = (e["source_ip"], e["username"])
        all_by_pair[pair].append(e)
        if e["outcome"] == "failure":
            fail_by_ip[e["source_ip"]].append(e)
            fail_by_pair[pair].append(e)

    # Rule 1: failed sign-ins from the same source.
    for ip, group in fail_by_ip.items():
        recent: deque = deque()
        last_fired = None
        for event in group:
            now = event["timestamp"]
            recent.append(event)
            while recent and now - recent[0]["timestamp"] > window:
                recent.popleft()
            if len(recent) >= config.failed_ip_threshold and (last_fired is None or now - last_fired >= cooldown):
                result.append(_alert(
                    "AUTH-001", now, list(recent), ip, MULTIPLE_ACCOUNTS,
                    f"{len(recent)} autenticaciones fallidas desde {ip} en {config.window_minutes} minutos.",
                ))
                last_fired = now

    # Rule 2: repeated attempts against a specific account.
    for (ip, username), group in fail_by_pair.items():
        recent = deque()
        last_fired = None
        for event in group:
            now = event["timestamp"]
            recent.append(event)
            while recent and now - recent[0]["timestamp"] > window:
                recent.popleft()
            if len(recent) >= config.failed_account_threshold and (last_fired is None or now - last_fired >= cooldown):
                result.append(_alert(
                    "AUTH-002", now, list(recent), ip, username,
                    f"{len(recent)} fallos para '{username}' desde {ip} dentro de {config.window_minutes} minutos.",
                ))
                last_fired = now

    # Rule 3: broad spraying pattern, O(n) amortized with sliding counters.
    limit = config.spraying_max_per_account
    for ip, group in fail_by_ip.items():
        recent = deque()
        counts: Counter = Counter()
        over_limit = 0  # accounts with more than `limit` failures in the current window
        last_fired = None
        for event in group:
            now = event["timestamp"]
            recent.append(event)
            counts[event["username"]] += 1
            if counts[event["username"]] == limit + 1:
                over_limit += 1
            while recent and now - recent[0]["timestamp"] > window:
                old_user = recent.popleft()["username"]
                if counts[old_user] == limit + 1:
                    over_limit -= 1
                counts[old_user] -= 1
                if counts[old_user] == 0:
                    del counts[old_user]
            if (len(counts) >= config.spraying_users_threshold
                and over_limit == 0
                and (last_fired is None or now - last_fired >= cooldown)):
                result.append(_alert(
                    "AUTH-003", now, list(recent), ip, MULTIPLE_ACCOUNTS,
                    f"{len(counts)} cuentas diferentes con fallos desde {ip}; un máximo de {limit} intentos por cuenta en la ventana.",
                ))
                last_fired = now

    # Rule 4: a valid session directly follows failures for same IP + account.
    # Severity is Critical only when the failures alone already reach the per-account
    # brute-force threshold; a few typos followed by a success are Medium.
    for (ip, username), group in all_by_pair.items():
        recent_failures = deque()
        for event in group:
            now = event["timestamp"]
            while recent_failures and now - recent_failures[0]["timestamp"] > window:
                recent_failures.popleft()
            if event["outcome"] == "failure":
                recent_failures.append(event)
            elif len(recent_failures) >= config.success_after_failures:
                severity = "Crítica" if len(recent_failures) >= config.failed_account_threshold else "Media"
                result.append(_alert(
                    "AUTH-004", now, list(recent_failures) + [event], ip, username,
                    f"Acceso correcto de '{username}' desde {ip} después de {len(recent_failures)} fallos recientes. Requiere verificación.",
                    severity=severity,
                ))
                recent_failures.clear()
            else:
                recent_failures.clear()

    # Rule 5: low-confidence contextual signal, disabled by default.
    if config.detect_offhours:
        zone = ZoneInfo(config.timezone)
        last_fired_by_pair = {}
        for event in records:
            if event["outcome"] != "success":
                continue
            now = event["timestamp"]
            local_time = now.to_pydatetime().astimezone(zone)
            if local_time.hour >= 6:
                continue
            key = (event["source_ip"], event["username"])
            if key in last_fired_by_pair and now - last_fired_by_pair[key] < timedelta(hours=6):
                continue
            result.append(_alert(
                "AUTH-005", now, [event], event["source_ip"], event["username"],
                f"Inicio de sesión a las {local_time:%H:%M} ({config.timezone}); puede ser legítimo.",
            ))
            last_fired_by_pair[key] = now

    result.sort(key=lambda x: (x["timestamp"], SEVERITY_ORDER[x["severity"]]), reverse=True)
    return pd.DataFrame.from_records(result, columns=list(ALERT_COLUMNS))
