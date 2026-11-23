import json

from sentinelai.detection import detect
from sentinelai.reporting import _safe_cell, to_csv, to_html, to_json


def test_json_html_and_csv(events_factory):
    specs = [(f'10:00:{n:02d}', '203.0.113.8', 'ana', 'failure') for n in range(9)]
    events = events_factory(specs)
    alerts = detect(events)
    result = json.loads(to_json(alerts, events))
    assert result['event_count'] == 9
    assert result['alert_count'] == len(alerts)
    assert 'AUTH-001' in to_csv(alerts)
    assert '<!doctype html>' in to_html(alerts, events).lower()
    assert 'attack.mitre.org' in to_html(alerts, events)


def test_csv_formula_injection_prevention():
    assert _safe_cell('=cmd|evil') == "'=cmd|evil"
    assert _safe_cell(' @SUM(A1)') == "' @SUM(A1)"
    assert _safe_cell('normal') == 'normal'


def test_html_escapes_user_data(events_factory):
    events = events_factory([(f'10:00:{n:02d}', '203.0.113.8', '<script>alert(1)</script>', 'failure') for n in range(9)])
    html = to_html(detect(events), events)
    assert '<script>' not in html
    assert '&lt;script&gt;' in html
