"""Offline, self-contained exports with HTML escaping and CSV-injection guards."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone
from html import escape

import pandas as pd

from sentinelai import __version__
from sentinelai.catalog import technique_url

PILL = {"Crítica": "crit", "Alta": "high", "Media": "med", "Baja": "low"}


def _records(alerts: pd.DataFrame) -> list[dict]:
    return [
        {k: (v.isoformat() if isinstance(v, (datetime, pd.Timestamp)) else v)
         for k, v in row.items()}
        for row in alerts.to_dict("records")
    ]


def who(alert: dict) -> str:
    """Human label for the account column; multi-account alerts have an empty username."""
    if alert.get("username"):
        return str(alert["username"])
    accounts = alert.get("accounts") or []
    return f"varias cuentas ({len(accounts)}{'+' if len(accounts) >= 20 else ''})"


def to_json(alerts: pd.DataFrame, events: pd.DataFrame, *, config=None, parsed=None, raw_input: bytes | None = None) -> str:
    """Machine-readable report. Records the configuration and input so it can be reproduced."""
    source = None
    if parsed is not None or raw_input is not None:
        source = {
            "sha256": hashlib.sha256(raw_input).hexdigest() if raw_input is not None else None,
            "format": getattr(parsed, "source_format", None),
            "total_rows": getattr(parsed, "total_rows", None),
            "dropped_rows": getattr(parsed, "dropped_rows", None),
            "dropped_reasons": getattr(parsed, "dropped_reasons", None),
            "notes": getattr(parsed, "notes", None),
        }
    return json.dumps({
        "schema_version": 2,
        "generator": f"SentinelAI {__version__}",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "alert_count": len(alerts),
        "config": asdict(config) if config is not None else None,
        "input": source,
        "alerts": _records(alerts),
    }, ensure_ascii=False, indent=2)


def _safe_cell(value: object) -> str:
    """Prevents exporting user-origin fields as spreadsheet formulas."""
    value = str(value if value is not None else "")
    if value and (value.startswith(("\t", "\r")) or value.lstrip().startswith(("=", "+", "-", "@"))):
        return "'" + value
    return value


def to_csv(alerts: pd.DataFrame) -> str:
    out = io.StringIO()
    fields = ["alert_id", "timestamp", "severity", "score", "rule_id", "title", "source_ip", "username", "accounts", "description", "mitre_id", "recommendation", "evidence_count"]
    writer = csv.writer(out)
    writer.writerow(fields)
    for row in alerts.to_dict("records"):
        row["accounts"] = "; ".join(row.get("accounts") or [])
        writer.writerow([_safe_cell(row.get(f, "")) for f in fields])
    return out.getvalue()


def to_html(alerts: pd.DataFrame, events: pd.DataFrame, *, config=None) -> str:
    counts = alerts["severity"].value_counts().to_dict() if len(alerts) else {}
    blocks = []
    for a in alerts.to_dict("records"):
        mitre_url = technique_url(str(a["mitre_id"]))
        blocks.append(f"""
        <article class="alert">
          <div class="line"><strong>{escape(str(a['title']))}</strong><span class="pill sev-{PILL.get(a['severity'], 'low')}">{escape(str(a['severity']))}</span></div>
          <p class="muted">{escape(str(a['timestamp']))} · {escape(str(a['source_ip']))} · {escape(who(a))}</p>
          <p>{escape(str(a['description']))}</p>
          <p><b>Recomendación:</b> {escape(str(a['recommendation']))}</p>
          <small>Regla {escape(str(a['rule_id']))} · <a href="{escape(mitre_url, quote=True)}">MITRE {escape(str(a['mitre_id']))}</a> · {a['evidence_count']} eventos correlacionados</small>
        </article>""")
    content = "\n".join(blocks) if blocks else "<p>No se detectaron alertas con esta configuración.</p>"
    cfg = ""
    if config is not None:
        cfg = "<p class=\"muted\">Configuración: " + escape(", ".join(f"{k}={v}" for k, v in asdict(config).items())) + "</p>"
    created = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelAI · Informe de seguridad</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0b1220;color:#e8effb;font:15px system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1024px;margin:auto;padding:48px 26px}}header{{border-bottom:1px solid #223149;padding-bottom:24px;margin-bottom:28px}}
h1{{font-size:38px;margin:0 0 6px}}h2{{font-size:21px;margin:32px 0 18px}}.accent{{color:#4ee0bb}}.muted,small{{color:#9aaec9}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.stat,.alert{{border:1px solid #223149;background:#111d31;border-radius:15px;padding:18px}}
.stat strong{{display:block;font-size:27px;color:#fff;margin:6px 0}}.line{{display:flex;justify-content:space-between;gap:20px;align-items:center}}.pill{{background:#573046;color:#ffd1da;padding:6px 10px;border-radius:9px;font-size:12px}}.sev-high{{background:#5a3b22;color:#ffd2a8}}.sev-med{{background:#4f4622;color:#ffe9a0}}.sev-low{{background:#1f3b52;color:#bfe3ff}}
.alert{{margin-bottom:14px}}a{{color:#65e7c2}}.notice{{background:#16273d;border-left:3px solid #4ee0bb;padding:14px 18px;margin:24px 0;border-radius:7px}}
@media(max-width:650px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:24px 16px}}}}
@media print{{body{{background:white;color:#111}}.stat,.alert{{background:white;color:#111;border-color:#ddd}}.muted,small{{color:#555}}.stat strong{{color:#111}}}}
</style></head><body><main>
<header><div class="accent">◆ SECURITY ANALYTICS · INFORME LOCAL</div><h1>SentinelAI</h1>
<div class="muted">Informe generado: {created}</div></header>
<div class="stats"><div class="stat">Eventos<strong>{len(events):,}</strong></div><div class="stat">Alertas<strong>{len(alerts)}</strong></div>
<div class="stat">Críticas<strong>{counts.get('Crítica',0)}</strong></div><div class="stat">Altas<strong>{counts.get('Alta',0)}</strong></div></div>
<div class="notice">Las alertas son hipótesis heurísticas. Una coincidencia no demuestra un ataque ni una cuenta comprometida. Confirmar siempre con evidencias adicionales.</div>
{cfg}<h2>Hallazgos e hipótesis</h2>{content}<footer class="muted">SentinelAI · Procesamiento local · MITRE ATT&amp;CK se usa como referencia de clasificación, no certificación de detección.</footer>
</main></body></html>"""
