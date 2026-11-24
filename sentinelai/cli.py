"""Run detections headlessly, e.g. for GitHub, a lab or shell demo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinelai.detection import DetectionConfig, detect
from sentinelai.parsers import ParseError, parse_bytes
from sentinelai.reporting import to_csv, to_html, to_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelAI · análisis offline de logs de autenticación")
    parser.add_argument("--input", type=Path, required=True, help="CSV, JSONL o auth.log")
    parser.add_argument("--format", choices=["csv", "jsonl", "ssh"], default="csv")
    parser.add_argument("--output", type=Path, default=Path("report.json"), help="Ruta de informe JSON")
    parser.add_argument("--html", type=Path, help="Informe HTML independiente")
    parser.add_argument("--csv", type=Path, help="Alertas CSV")
    parser.add_argument("--ssh-year", type=int, default=None, help="Año de la primera línea syslog (por defecto, el año actual)")
    parser.add_argument("--dayfirst", choices=["auto", "dmy", "mdy"], default="auto", help="Interpretación de fechas dd/mm vs mm/dd")
    parser.add_argument("--window", type=int, default=10, help="Ventana de correlación en minutos")
    parser.add_argument("--offhours", action="store_true", help="Activar regla contextual de accesos nocturnos")
    parser.add_argument("--timezone", default="Europe/Madrid", help="Zona horaria IANA de la regla nocturna")
    args = parser.parse_args(argv)
    try:
        raw = args.input.read_bytes()
        dayfirst = {"auto": None, "dmy": True, "mdy": False}[args.dayfirst]
        parsed = parse_bytes(raw, args.format, ssh_year=args.ssh_year, dayfirst=dayfirst)
        config = DetectionConfig(window_minutes=args.window, detect_offhours=args.offhours, timezone=args.timezone)
        alerts = detect(parsed.events, config)
        for dest, content in [(args.output, to_json(alerts, parsed.events, config=config, parsed=parsed, raw_input=raw)),
                              (args.html, to_html(alerts, parsed.events, config=config)) if args.html else (None, ""),
                              (args.csv, to_csv(alerts)) if args.csv else (None, "")]:
            if dest is not None:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
        print(f"Eventos válidos: {len(parsed.events)} | Descartados: {parsed.dropped_rows} | Alertas: {len(alerts)}")
        for reason, n in parsed.dropped_reasons.items():
            print(f"  · descartados por {reason}: {n}")
        for note in parsed.notes:
            print(f"  ! {note}")
        for a in alerts.head(10).itertuples():
            print(f"  {a.severity:7s} [{a.rule_id}] {a.source_ip:18s} {a.title}")
        print(f"Informe JSON: {args.output}")
        return 0
    except (OSError, ParseError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
