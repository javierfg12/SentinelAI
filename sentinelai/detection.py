"""Explainable sliding-window correlation rules for authentication events."""

from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import dataclass
from datetime import timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pandas as pd

from sentinelai.catalog import RULES

SEVERITY_ORDER = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}


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

    def validate(self) -> None:
        for field in ("window_minutes", "cooldown_minutes", "failed_ip_threshold", "failed_account_threshold", "spraying_users_threshold", "success_after_failures"):
            if getattr(self, field) < 1:
                raise ValueError(f"{field} debe ser positivo")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Zona horaria no reconocida") from exc


def _alert(rule_id: str, occurred: pd.Timestamp, evidence: list, source_ip: str, username: str, detail: str) -> dict:
    rule = RULES[rule_id]
    evidences = [x["event_id"] for x in evidence]
    seed = f"{rule_id}:{occurred.isoformat()}:{source_ip}:{username}:{','.join(evidences)}"
    return {
        "alert_id": hashlib.sha256(seed.encode()).hexdigest()[:10].upper(),
        "rule_id": rule_id,
        "title": rule["title"],
        "severity": rule["severity"],
        "score": {"AUTH-001": 82, "AUTH-002": 80, "AUTH-003": 88, "AUTH-004": 95, "AUTH-005": 30}[rule_id],
        "timestamp": occurred.isoformat(),
        "source_ip": source_ip,
        "username": username,
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
        return pd.DataFrame(columns=[
            "alert_id", "rule_id", "title", "severity", "score", "timestamp",
            "source_ip", "username", "description", "mitre_id", "mitre_name",
            "recommendation", "evidence_count", "evidence_ids",
        ])

    ordered = events.sort_values(["timestamp", "event_id"])
    failures = ordered[ordered["outcome"] == "failure"]
    successes = ordered[ordered["outcome"] == "success"]
    window = timedelta(minutes=config.window_minutes)
    cooldown = timedelta(minutes=config.cooldown_minutes)
    result: list[dict] = []

    # Rule 1: failed sign-ins from the same source.
    for ip, group in failures.groupby("source_ip", sort=False):
        recent: deque = deque()
        last_fired = None
        for event in group.to_dict("records"):
            now = event["timestamp"]
            recent.append(event)
            while recent and now - recent[0]["timestamp"] > window:
                recent.popleft()
            if len(recent) >= config.failed_ip_threshold and (last_fired is None or now - last_fired >= cooldown):
                result.append(_alert(
                    "AUTH-001", now, list(recent), ip, "Varias cuentas",
                    f"{len(recent)} autenticaciones fallidas desde {ip} en {config.window_minutes} minutos.",
                ))
                last_fired = now

    # Rule 2: repeated attempts against a specific account.
    for (ip, username), group in failures.groupby(["source_ip", "username"], sort=False):
        recent = deque()
        last_fired = None
        for event in group.to_dict("records"):
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
    for ip, group in failures.groupby("source_ip", sort=False):
        recent = deque()
        counts: Counter = Counter()
        over_two = 0  # number of accounts with >2 failures in current window
        last_fired = None
        for event in group.to_dict("records"):
            now = event["timestamp"]
            user = event["username"]
            recent.append(event)
            counts[user] += 1
            if counts[user] == 3:
                over_two += 1
            while recent and now - recent[0]["timestamp"] > window:
                expired = recent.popleft()
                old_user = expired["username"]
                if counts[old_user] == 3:
                    over_two -= 1
                counts[old_user] -= 1
                if counts[old_user] == 0:
                    del counts[old_user]
            if (len(counts) >= config.spraying_users_threshold
                and over_two == 0
                and (last_fired is None or now - last_fired >= cooldown)):
                result.append(_alert(
                    "AUTH-003", now, list(recent), ip, "Varias cuentas",
                    f"{len(counts)} cuentas diferentes con fallos desde {ip}; un máximo de 2 intentos por cuenta en la ventana.",
                ))
                last_fired = now

    # Rule 4: a valid session directly follows failures for same IP + account.
    for (ip, username), group in ordered.groupby(["source_ip", "username"], sort=False):
        recent_failures = deque()
        for event in group.to_dict("records"):
            now = event["timestamp"]
            while recent_failures and now - recent_failures[0]["timestamp"] > window:
                recent_failures.popleft()
            if event["outcome"] == "failure":
                recent_failures.append(event)
            elif len(recent_failures) >= config.success_after_failures:
                evidence = list(recent_failures) + [event]
                result.append(_alert(
                    "AUTH-004", now, evidence, ip, username,
                    f"Acceso correcto de '{username}' desde {ip} después de {len(recent_failures)} fallos recientes. Requiere verificación.",
                ))
                recent_failures.clear()
            else:
                recent_failures.clear()

    # Rule 5: low-confidence contextual signal, disabled by default.
    if config.detect_offhours:
        zone = ZoneInfo(config.timezone)
        last_fired_by_pair = {}
        for event in successes.to_dict("records"):
            now = event["timestamp"]
            local_hour = now.to_pydatetime().astimezone(zone).hour
            if local_hour >= 6:
                continue
            key = (event["source_ip"], event["username"])
            if key in last_fired_by_pair and now - last_fired_by_pair[key] < timedelta(hours=6):
                continue
            result.append(_alert(
                "AUTH-005", now, [event], event["source_ip"], event["username"],
                f"Inicio de sesión a las {now.to_pydatetime().astimezone(zone):%H:%M} ({config.timezone}); puede ser legítimo.",
            ))
            last_fired_by_pair[key] = now

    result.sort(key=lambda x: (x["timestamp"], SEVERITY_ORDER[x["severity"]]), reverse=True)
    return pd.DataFrame.from_records(result, columns=[
        "alert_id", "rule_id", "title", "severity", "score", "timestamp",
        "source_ip", "username", "description", "mitre_id", "mitre_name",
        "recommendation", "evidence_count", "evidence_ids",
    ])
