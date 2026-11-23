"""Build a self-contained, read-only recruiter demo from the real rule engine.

This HTML is an offline snapshot; only the Python/Streamlit app analyzes new uploads.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelai.detection import detect
from sentinelai.parsers import parse_bytes

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    events = parse_bytes((ROOT / "data/demo_auth.csv").read_bytes(), "csv").events
    alerts = detect(events)
    data = {
        "events": [
            {"timestamp": e["timestamp"].isoformat(), "ip": e["source_ip"], "user": e["username"], "outcome": e["outcome"], "service": e["service"], "event_id": e["event_id"]}
            for e in events.to_dict("records")
        ],
        "alerts": alerts.to_dict("records"),
    }
    template = (ROOT / "assets" / "preview_template.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = template.replace("__SENTINEL_DATA__", payload)
    (ROOT / "ABRIR-DEMO.html").write_text(html, encoding="utf-8")
    print(f"Built offline preview: {len(events)} events, {len(alerts)} correlated alerts")


if __name__ == "__main__":
    main()
