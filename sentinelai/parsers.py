"""CSV, JSONL and OpenSSH auth.log ingestion with strict, visible normalization.

All stored timestamps are UTC; input without a timezone is interpreted as UTC.
Supported timestamps: ISO 8601, syslog, epoch (s/ms) and dd/mm/yyyy or mm/dd/yyyy
(see ``dayfirst``). Ambiguous dates are never guessed silently: a note is returned.
No network request occurs, and unknown log patterns are not guessed.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 100_000
REQUIRED = ("timestamp", "source_ip", "username", "outcome")
COLUMNS = ("event_id", "timestamp", "source_ip", "username", "outcome", "service", "country", "user_agent", "raw_event")
ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "date", "@timestamp"),
    "source_ip": ("source_ip", "src_ip", "ip", "client_ip", "remote_ip"),
    "username": ("username", "user", "account", "principal"),
    "outcome": ("outcome", "status", "result", "event_outcome"),
    "service": ("service", "application", "app", "protocol"),
    "country": ("country", "geo_country"),
    "user_agent": ("user_agent", "agent"),
}
SUCCESS = {"success", "successful", "ok", "accepted", "passed", "true", "1", "éxito", "exito"}
FAILURE = {"failure", "failed", "fail", "denied", "invalid", "false", "0", "error", "fallo"}
SSH_LINE = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\S+))"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<status>Failed|Accepted)\s+(?P<method>password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+(?:\s+ssh2)?.*$"
)
_MONTHS = {m: n for n, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_NUMERIC_TS = re.compile(r"^\d{9,13}(?:\.\d+)?$")
_LOCAL_DATE = re.compile(r"^\s*(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{2,4})\b")


class ParseError(ValueError):
    """Input cannot be analyzed safely or meaningfully."""


@dataclass
class ParseResult:
    events: pd.DataFrame
    dropped_rows: int
    total_rows: int
    source_format: str
    dropped_reasons: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _check_size(data: bytes) -> None:
    if not data:
        raise ParseError("El archivo está vacío.")
    if len(data) > MAX_INPUT_BYTES:
        raise ParseError("Archivo demasiado grande: límite de 10 MB por análisis.")


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError("El archivo debe estar codificado en UTF-8.") from exc


def parse_bytes(data: bytes, fmt: str, *, ssh_year: int | None = None, dayfirst: bool | None = None) -> ParseResult:
    """Parse a binary upload as csv, jsonl or ssh without contacting external services.

    ``ssh_year`` is the year of the FIRST syslog line (default: current year); a
    December -> January rollover inside the file is handled. ``dayfirst`` forces
    dd/mm (True) or mm/dd (False); None auto-detects and notes real ambiguity.
    """
    _check_size(data)
    content = _decode(data)
    if fmt == "csv":
        try:
            raw = pd.read_csv(io.StringIO(content), dtype=str, keep_default_na=False)
        except (pd.errors.ParserError, ValueError, UnicodeError) as exc:
            raise ParseError(f"CSV no válido: {exc}") from exc
        if len(raw) > MAX_EVENTS:
            raise ParseError("Demasiados eventos (máximo 100.000).")
        return normalize(raw, "csv", dayfirst=dayfirst)
    if fmt == "jsonl":
        records: list[dict] = []
        for n, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"JSON inválido en línea {n}: {exc.msg}") from exc
            if not isinstance(obj, dict):
                raise ParseError(f"La línea {n} debe contener un objeto JSON.")
            records.append(obj)
            if len(records) > MAX_EVENTS:
                raise ParseError("Demasiados eventos (máximo 100.000).")
        return normalize(pd.DataFrame.from_records(records), "jsonl", dayfirst=dayfirst)
    if fmt == "ssh":
        year = ssh_year if ssh_year is not None else datetime.now(timezone.utc).year
        if not 2000 <= year <= 2100:
            raise ParseError("Año SSH fuera del rango permitido (2000-2100).")
        records = []
        lines = [line for line in content.splitlines() if line.strip()]
        if len(lines) > MAX_EVENTS:
            raise ParseError("Demasiadas líneas (máximo 100.000).")
        prev_month = None
        for line in lines:
            found = SSH_LINE.match(line)
            if not found:
                continue
            d = found.groupdict()
            if d["iso"]:
                stamp = d["iso"]
            else:
                month = _MONTHS.get(d["month"])
                if month is None:
                    continue
                if prev_month is not None and prev_month - month > 6:
                    year += 1  # December -> January rollover
                prev_month = month
                stamp = f"{d['month']} {d['day']} {year} {d['clock']}"
            records.append({
                "timestamp": stamp,
                "source_ip": d["ip"],
                "username": d["username"],
                "outcome": "failure" if d["status"] == "Failed" else "success",
                "service": "sshd",
                "raw_event": line,
            })
        unrelated = len(lines) - len(records)
        result = normalize(pd.DataFrame.from_records(records), "ssh", dayfirst=dayfirst)
        result.total_rows = len(lines)
        result.dropped_rows = len(lines) - len(result.events)
        if unrelated:
            result.dropped_reasons["líneas que no son un inicio de sesión sshd (cron, sudo, etc.; se ignoran a propósito)"] = unrelated
        return result
    raise ParseError("Formato desconocido. Usa csv, jsonl o ssh.")


def normalize(raw: pd.DataFrame, source_format: str = "csv", *, dayfirst: bool | None = None) -> ParseResult:
    """Normalize optional aliases; explicitly reject rows missing valid core attributes."""
    if raw.empty:
        raise ParseError("No se encontraron eventos de autenticación compatibles.")
    if len(raw) > MAX_EVENTS:
        raise ParseError("Demasiados eventos (máximo 100.000).")
    raw = raw.copy()
    raw.columns = [str(c).strip().lower() for c in raw.columns]
    renames = {}
    for target, names in ALIASES.items():
        found = next((name for name in names if name in raw.columns), None)
        if found is not None:
            renames[found] = target
    raw = raw.rename(columns=renames)
    missing = [col for col in REQUIRED if col not in raw.columns]
    if missing:
        raise ParseError("Faltan columnas obligatorias: " + ", ".join(missing))
    for col in ("service", "country", "user_agent", "raw_event"):
        if col not in raw.columns:
            raw[col] = ""
    raw = raw[list(REQUIRED) + ["service", "country", "user_agent", "raw_event"]]
    raw = raw.fillna("")
    for col in ("source_ip", "username", "outcome", "service", "country", "user_agent", "raw_event"):
        raw[col] = raw[col].astype(str).str.strip()
    raw["outcome"] = raw["outcome"].str.lower().map(
        lambda status: "success" if status in SUCCESS else "failure" if status in FAILURE else ""
    )
    timestamps, notes = _parse_timestamps(raw["timestamp"], dayfirst)
    ip_values = raw["source_ip"].drop_duplicates().tolist()
    valid_ips = {}
    for ip in ip_values:
        try:
            valid_ips[ip] = bool(ipaddress.ip_address(ip))
        except ValueError:
            valid_ips[ip] = False
    ip_ok = raw["source_ip"].map(valid_ips)
    valid = timestamps.notna() & ip_ok & raw["username"].ne("") & raw["outcome"].ne("")
    reasons = {
        "fecha no reconocida": int(timestamps.isna().sum()),
        "IP inválida": int((~ip_ok).sum()),
        "usuario vacío": int(raw["username"].eq("").sum()),
        "resultado desconocido (usa success/failure)": int(raw["outcome"].eq("").sum()),
    }
    reasons = {k: v for k, v in reasons.items() if v}
    total = len(raw)
    clean = raw.loc[valid].copy()
    if clean.empty:
        detail = "; ".join(f"{k}: {v}" for k, v in reasons.items())
        raise ParseError("Ningún evento tiene fecha, IP, usuario y resultado válidos. Motivos: " + detail)
    clean["timestamp"] = timestamps.loc[valid]
    clean["service"] = clean["service"].replace("", "unknown")
    clean["country"] = clean["country"].replace("", "Unknown")
    # Event ID is stable across reruns and unique even for identical duplicated lines.
    clean["event_id"] = [
        hashlib.sha256(f"{source_format}:{idx}:{t.isoformat()}:{ip}:{user}:{out}".encode()).hexdigest()[:12]
        for idx, t, ip, user, out in zip(
            clean.index,
            clean["timestamp"],
            clean["source_ip"],
            clean["username"],
            clean["outcome"],
            strict=True,
        )
    ]
    clean = clean.loc[:, list(COLUMNS)].sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    return ParseResult(events=clean, dropped_rows=total - len(clean), total_rows=total, source_format=source_format,
                       dropped_reasons=reasons, notes=notes)


def _parse_timestamps(values: pd.Series, dayfirst: bool | None) -> tuple[pd.Series, list[str]]:
    """Parse mixed timestamps to UTC without silently swapping day and month."""
    text = values.astype(str).str.strip()
    notes: list[str] = []
    parts: list[pd.Series] = []
    numeric = text.str.match(_NUMERIC_TS)
    if numeric.any():
        nums = pd.to_numeric(text[numeric], errors="coerce")
        seconds = nums.where(nums < 1e11, nums / 1000)  # >=1e11 is epoch in milliseconds
        parts.append(pd.to_datetime(seconds, unit="s", utc=True, errors="coerce"))
        notes.append("Marcas de tiempo numéricas interpretadas como epoch (segundos o milisegundos).")
    local = text.str.match(_LOCAL_DATE) & ~numeric
    if local.any():
        fields = text[local].str.extract(_LOCAL_DATE).astype(int)
        first_gt12, second_gt12 = bool((fields[0] > 12).any()), bool((fields[1] > 12).any())
        if dayfirst is None:
            use_dayfirst = not (second_gt12 and not first_gt12)
            if not first_gt12 and not second_gt12:
                notes.append("Fechas dd/mm/aaaa ambiguas: se interpretan como día/mes. "
                             "Si tu log usa mes/día, indícalo con dayfirst=False.")
        else:
            use_dayfirst = dayfirst
        parts.append(pd.to_datetime(text[local], dayfirst=use_dayfirst, utc=True, errors="coerce", format="mixed"))
    rest = ~(numeric | local)
    if rest.any():
        parts.append(pd.to_datetime(text[rest], utc=True, errors="coerce", format="mixed"))
    return pd.concat(parts).reindex(text.index), notes
