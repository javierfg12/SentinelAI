"""Generate a safe, repeatable, fully synthetic authentication dataset.

Only reserved documentation and RFC1918 IP ranges are used.
"""

from __future__ import annotations

import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data"
BASE = datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)
USERS = ["ana", "carlos", "lucia", "marta", "jorge", "sofia", "diego", "elena", "julia", "pablo", "admin", "finance"]


def generate() -> list[dict[str, str]]:
    r = random.Random(20261120)
    events: list[dict[str, str]] = []

    def add(at: datetime, ip: str, username: str, outcome: str, service: str = "vpn", country: str = "ES") -> None:
        events.append({
            "timestamp": at.isoformat(), "source_ip": ip, "username": username,
            "outcome": outcome, "service": service, "country": country,
            "user_agent": "SentinelAI demo client/1.0", "raw_event": "synthetic-event",
        })

    # Mostly normal events from private network; occasional benign failures.
    for day in range(3):
        for hour in range(8, 21):
            for _ in range(18):
                ts = BASE + timedelta(days=day, hours=hour-8, minutes=r.randint(0,59), seconds=r.randint(0,59))
                ip = f"10.20.0.{r.randint(10,44)}"
                add(ts, ip, r.choice(USERS[:10]), "failure" if r.random() < .075 else "success")

    attack_day = BASE + timedelta(days=1)
    # Scenario A: 13 rapid failures from one external documentation IP.
    for n in range(13):
        add(attack_day + timedelta(hours=5, seconds=n*31), "203.0.113.71", "admin", "failure", "ssh", "Unknown")
    # Scenario B: 9 separate usernames with 1 failure each.
    for n, user in enumerate(USERS[:9]):
        add(attack_day + timedelta(hours=7, seconds=n*43), "203.0.113.72", user, "failure", "vpn", "Unknown")
    # Scenario C: successful login after six failures, suspicious but not confirmed.
    for n in range(6):
        add(attack_day + timedelta(hours=9, seconds=n*50), "198.51.100.73", "finance", "failure", "vpn", "Unknown")
    add(attack_day + timedelta(hours=9, seconds=6*50), "198.51.100.73", "finance", "success", "vpn", "Unknown")
    # Scenario D: off-hours valid access (context only).
    add(BASE + timedelta(days=2, hours=-6), "198.51.100.16", "admin", "success", "ssh", "Unknown")
    events.sort(key=lambda e: e["timestamp"])
    return events


def main() -> None:
    DEST.mkdir(exist_ok=True)
    data = generate()
    with (DEST / "demo_auth.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(data[0]))
        writer.writeheader()
        writer.writerows(data)
    with (DEST / "demo_auth.jsonl").open("w", encoding="utf-8") as f:
        for event in data:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    ssh_lines = []
    for n in range(8):
        at = BASE + timedelta(days=1, hours=5, seconds=n*50)
        ssh_lines.append(f"{at:%b} {at.day:2d} {at:%H:%M:%S} lab sshd[{2100+n}]: Failed password for invalid user demo from 203.0.113.71 port 52500 ssh2")
    at = BASE + timedelta(days=1, hours=5, minutes=8)
    ssh_lines.append(f"{at:%b} {at.day:2d} {at:%H:%M:%S} lab sshd[2135]: Accepted publickey for demo from 203.0.113.71 port 52500 ssh2")
    (DEST / "demo_ssh.log").write_text("\n".join(ssh_lines) + "\n", encoding="utf-8")
    print(f"Generated {len(data)} synthetic events and {len(ssh_lines)} SSH log lines in {DEST}")


if __name__ == "__main__":
    main()
