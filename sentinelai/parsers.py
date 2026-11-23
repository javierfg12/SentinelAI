"""CSV, JSONL and OpenSSH auth.log ingestion with strict, visible normalization.

All stored timestamps are UTC; input without a timezone is interpreted as UTC.
No network request occurs, and unknown log patterns are not guessed.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass

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
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed password|Accepted password|Accepted publickey)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+\s+ssh2.*$"
)


class ParseError(ValueError):
    """Input cannot be analyzed safely or meaningfully."""


@dataclass
class ParseResult:
    events: pd.DataFrame
    dropped_rows: int
    total_rows: int
    source_format: str


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


def parse_bytes(data: bytes, fmt: str, *, ssh_year: int = 2026) -> ParseResult:
    """Parse a binary upload as csv, jsonl or ssh without contacting external services."""
    _check_size(data)
    content = _decode(data)
    if fmt == "csv":
        try:
            raw = pd.read_csv(io.StringIO(content), dtype=str, keep_default_na=False)
        except (pd.errors.ParserError, ValueError, UnicodeError) as exc:
            raise ParseError(f"CSV no válido: {exc}") from exc
        if len(raw) > MAX_EVENTS:
            raise ParseError("Demasiados eventos (máximo 100.000).")
        return normalize(raw, "csv")
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
        return normalize(pd.DataFrame.from_records(records), "jsonl")
    if fmt == "ssh":
        if not 2000 <= ssh_year <= 2100:
            raise ParseError("Año SSH fuera del rango permitido (2000-2100).")
        records = []
        lines = [line for line in content.splitlines() if line.strip()]
        if len(lines) > MAX_EVENTS:
            raise ParseError("Demasiadas líneas (máximo 100.000).")
        for line in lines:
            found = SSH_LINE.match(line)
            if not found:
                continue
            d = found.groupdict()
            records.append({
                "timestamp": f"{d['month']} {d['day']} {ssh_year} {d['clock']}",
                "source_ip": d["ip"],
                "username": d["username"],
                "outcome": "failure" if d["status"] == "Failed password" else "success",
                "service": "sshd",
                "raw_event": line,
            })
        result = normalize(pd.DataFrame.from_records(records), "ssh")
        result.total_rows = len(lines)
        result.dropped_rows = len(lines) - len(result.events)
        return result
    raise ParseError("Formato desconocido. Usa csv, jsonl o ssh.")


def normalize(raw: pd.DataFrame, source_format: str = "csv") -> ParseResult:
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
    # Explicitly parse heterogeneous ISO8601 timestamps and syslog dates in UTC.
    timestamps = pd.to_datetime(raw["timestamp"], utc=True, errors="coerce", format="mixed")
    ip_values = raw["source_ip"].drop_duplicates().tolist()
    valid_ips = {}
    for ip in ip_values:
        try:
            valid_ips[ip] = bool(ipaddress.ip_address(ip))
        except ValueError:
            valid_ips[ip] = False
    valid = (
        timestamps.notna()
        & raw["source_ip"].map(valid_ips)
        & raw["username"].ne("")
        & raw["outcome"].ne("")
    )
    total = len(raw)
    clean = raw.loc[valid].copy()
    if clean.empty:
        raise ParseError("Ningún evento tiene fecha, IP, usuario y resultado válidos.")
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
        )
    ]
    clean = clean.loc[:, list(COLUMNS)].sort_values(["timestamp", "event_id"]).reset_index(drop=True)
    return ParseResult(events=clean, dropped_rows=total - len(clean), total_rows=total, source_format=source_format)
