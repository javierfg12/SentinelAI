"""Regression tests for bugs found in the project review."""

from __future__ import annotations

import json
import time

import pandas as pd
import pytest

from sentinelai.detection import DetectionConfig, detect
from sentinelai.parsers import ParseError, normalize, parse_bytes
from sentinelai.reporting import _safe_cell, to_csv, to_html, to_json


def _csv(*rows: str) -> bytes:
    return ("timestamp,source_ip,username,outcome\n" + "\n".join(rows) + "\n").encode()


# --- dates -----------------------------------------------------------------------------------
def test_ambiguous_dd_mm_dates_are_read_day_first_and_noted():
    result = parse_bytes(_csv("03/11/2026 10:00:00,203.0.113.5,ana,failure", "04/05/2026 09:00:00,203.0.113.5,ana,success"), "csv")
    assert result.events["timestamp"].dt.strftime("%Y-%m-%d").tolist() == ["2026-05-04", "2026-11-03"]
    assert any("ambiguas" in note for note in result.notes)


def test_mixed_unambiguous_dates_are_consistent():
    result = parse_bytes(_csv("25/11/2026 10:00:00,203.0.113.5,ana,failure", "03/11/2026 10:00:00,203.0.113.5,ana,failure"), "csv")
    assert result.events["timestamp"].dt.strftime("%Y-%m-%d").tolist() == ["2026-11-03", "2026-11-25"]


def test_month_first_is_detected_or_forced():
    auto = parse_bytes(_csv("11/25/2026 10:00:00,203.0.113.5,ana,failure"), "csv")
    assert auto.events["timestamp"].iloc[0].strftime("%Y-%m-%d") == "2026-11-25"
    forced = parse_bytes(_csv("03/11/2026 10:00:00,203.0.113.5,ana,failure"), "csv", dayfirst=False)
    assert forced.events["timestamp"].iloc[0].strftime("%Y-%m-%d") == "2026-03-11"


def test_epoch_seconds_and_milliseconds():
    result = parse_bytes(_csv("1763640000,203.0.113.5,ana,failure", "1763640060000,203.0.113.5,ana,failure"), "csv")
    assert result.events["timestamp"].dt.strftime("%Y-%m-%d %H:%M").tolist() == ["2025-11-20 12:00", "2025-11-20 12:01"]


def test_error_message_explains_why_rows_were_rejected():
    with pytest.raises(ParseError, match="fecha no reconocida"):
        parse_bytes(_csv("no-es-fecha,203.0.113.5,ana,failure"), "csv")


def test_dropped_reasons_are_reported():
    result = parse_bytes(_csv("2026-11-20T10:00:00Z,203.0.113.5,ana,failure", "2026-11-20T10:00:00Z,999.1.1.1,ana,failure"), "csv")
    assert result.dropped_rows == 1 and result.dropped_reasons == {"IP inválida": 1}


# --- ssh -------------------------------------------------------------------------------------
SSH = """Nov 21 13:00:01 srv sshd[1]: Failed password for invalid user test from 203.0.113.9 port 4000 ssh2
Nov 21 13:00:02 srv CRON[22]: pam_unix(cron:session): session opened for user root
Nov 21 13:00:03 srv sudo: ana : TTY=pts/0 ; COMMAND=/bin/ls
Nov 21 13:00:05 srv sshd[3]: Accepted keyboard-interactive/pam for ana from 203.0.113.10 port 5000 ssh2
Nov 21 13:00:06 srv sshd[4]: Failed publickey for root from 2001:db8::1 port 22 ssh2
"""


def test_ssh_reads_pam_publickey_and_ipv6_and_counts_unrelated_lines():
    result = parse_bytes(SSH.encode(), "ssh", ssh_year=2026)
    assert result.events["outcome"].tolist() == ["failure", "success", "failure"]
    assert sum(result.dropped_reasons.values()) == 2  # cron + sudo, ignored on purpose


def test_ssh_iso_timestamps():
    line = "2026-11-21T13:00:00.123456+01:00 srv sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2\n"
    event = parse_bytes(line.encode(), "ssh").events.iloc[0]
    assert event["timestamp"].isoformat().startswith("2026-11-21T12:00:00")


def test_ssh_year_rollover_december_to_january():
    log = (
        "Dec 31 23:59:00 srv sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
        "Jan  1 00:01:00 srv sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2\n"
    )
    years = parse_bytes(log.encode(), "ssh", ssh_year=2026).events["timestamp"].dt.year.tolist()
    assert years == [2026, 2027]


# --- detection -------------------------------------------------------------------------------
def test_success_after_few_failures_is_medium_not_critical(events_factory):
    events = events_factory([("10:00:00", "10.20.0.5", "ana", "failure"), ("10:01:00", "10.20.0.5", "ana", "failure"),
                             ("10:02:00", "10.20.0.5", "ana", "failure"), ("10:03:00", "10.20.0.5", "ana", "success")])
    alert = detect(events).iloc[0]
    assert (alert["rule_id"], alert["severity"]) == ("AUTH-004", "Media") and alert["score"] < 95


def test_success_after_brute_force_level_failures_is_critical(events_factory):
    specs = [(f"10:0{i}:00", "198.51.100.7", "ana", "failure") for i in range(5)] + [("10:06:00", "198.51.100.7", "ana", "success")]
    alerts = detect(events_factory(specs))
    assert alerts[alerts["rule_id"] == "AUTH-004"].iloc[0]["severity"] == "Crítica"


def test_multi_account_alerts_use_empty_username_and_list_accounts(events_factory):
    specs = [(f"10:0{i}:00", "203.0.113.72", f"user{i}", "failure") for i in range(8)]
    alert = detect(events_factory(specs)).query("rule_id == 'AUTH-001'").iloc[0]
    assert alert["username"] == "" and len(alert["accounts"]) == 8


def test_spraying_tolerates_configured_attempts_per_account(events_factory):
    specs = [(f"10:{n:02d}:{k:02d}", "203.0.113.80", f"user{n}", "failure") for n in range(6) for k in (0, 30)]
    assert "AUTH-003" in detect(events_factory(specs))["rule_id"].tolist()  # 2 attempts per account
    three = [(f"10:{n:02d}:{k:02d}", "203.0.113.80", f"user{n}", "failure") for n in range(6) for k in (0, 20, 40)]
    assert "AUTH-003" not in detect(events_factory(three))["rule_id"].tolist()
    assert "AUTH-003" in detect(events_factory(three), DetectionConfig(spraying_max_per_account=3))["rule_id"].tolist()


def test_detection_scales_with_many_distinct_ip_user_pairs():
    n = 20_000
    frame = pd.DataFrame({
        "timestamp": pd.date_range("2026-11-20", periods=n, freq="s", tz="UTC").astype(str),
        "source_ip": [f"10.0.{i % 200}.{i % 250 + 1}" for i in range(n)],
        "username": [f"user{i % 3000}" for i in range(n)],
        "outcome": ["failure" if i % 3 == 0 else "success" for i in range(n)],
    })
    events = normalize(frame).events
    start = time.perf_counter()
    detect(events)
    assert time.perf_counter() - start < 10


# --- reporting -------------------------------------------------------------------------------
def test_json_report_records_configuration_and_input(events_factory):
    events = events_factory([("10:00:00", "203.0.113.1", "ana", "failure")])
    raw = _csv("2026-11-20T10:00:00Z,203.0.113.1,ana,failure")
    parsed = parse_bytes(raw, "csv")
    report = json.loads(to_json(detect(events), events, config=DetectionConfig(window_minutes=7), parsed=parsed, raw_input=raw))
    assert report["config"]["window_minutes"] == 7 and len(report["input"]["sha256"]) == 64
    assert report["generator"].startswith("SentinelAI 1.")


def test_csv_guard_covers_tabs_and_html_severity_class(events_factory):
    assert _safe_cell("\t=1+1").startswith("'") and _safe_cell("\r@x").startswith("'")
    specs = [(f"10:0{i}:00", "198.51.100.7", "ana", "failure") for i in range(5)] + [("10:06:00", "198.51.100.7", "ana", "success")]
    events = events_factory(specs)
    alerts = detect(events)
    assert "sev-high" in to_html(alerts, events) and "AUTH-004" in to_csv(alerts)
