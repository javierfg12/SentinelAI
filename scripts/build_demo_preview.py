"""Build a self-contained, read-only recruiter demo from the real rule engine.

This HTML is an offline snapshot; only the Python/Streamlit app analyzes new uploads.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelai import __version__
from sentinelai.catalog import RULES
from sentinelai.detection import detect
from sentinelai.parsers import parse_bytes

ROOT = Path(__file__).resolve().parents[1]


def build_html() -> tuple[str, int, int]:
    """Return (html, event_count, alert_count); deterministic so CI can check it is up to date."""
    events = parse_bytes((ROOT / "data/demo_auth.csv").read_bytes(), "csv").events
    alerts = detect(events)
    data = {
        "meta": {"version": __version__, "source": "data/demo_auth.csv"},
        "rules": [{"id": k, **v} for k, v in RULES.items()],
        "events": [
            {"timestamp": e["timestamp"].isoformat(), "ip": e["source_ip"], "user": e["username"], "outcome": e["outcome"], "service": e["service"], "event_id": e["event_id"]}
            for e in events.to_dict("records")
        ],
        "alerts": alerts.to_dict("records"),
    }
    template = (ROOT / "assets" / "preview_template.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return template.replace("__SENTINEL_DATA__", payload), len(events), len(alerts)


def main() -> None:
    html, n_events, n_alerts = build_html()
    (ROOT / "index.html").write_text(html, encoding="utf-8")
    print(f"Built offline preview (index.html): {n_events} events, {n_alerts} correlated alerts")


if __name__ == "__main__":
    main()
