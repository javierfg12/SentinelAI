from pathlib import Path

import pytest

from sentinelai.detection import DetectionConfig, detect
from sentinelai.parsers import parse_bytes

ROOT = Path(__file__).resolve().parents[1]


def test_demo_contains_expected_scenarios():
    events = parse_bytes((ROOT / 'data/demo_auth.csv').read_bytes(), 'csv').events
    alerts = detect(events)
    assert {'AUTH-001', 'AUTH-002', 'AUTH-003', 'AUTH-004'}.issubset(set(alerts['rule_id']))
    assert 'AUTH-005' not in set(alerts['rule_id'])
    assert set(alerts[alerts['rule_id']=='AUTH-003']['source_ip']) == {'203.0.113.72'}
    assert set(alerts[alerts['rule_id']=='AUTH-004']['username']) == {'finance'}


def test_no_false_positives_for_normal_auth(events_factory):
    events = events_factory([(f'10:{n:02d}:00', '10.0.0.1', 'ana', 'success') for n in range(15)])
    assert detect(events).empty


def test_spread_out_failures_do_not_trigger(events_factory):
    events = events_factory([(f'{n:02d}:00:00', '10.0.0.2', 'ana', 'failure') for n in range(8)])
    assert detect(events).empty


def test_password_spray_is_distinct_accounts(events_factory):
    events = events_factory([(f'10:0{n}:00', '203.0.113.30', f'user{n}', 'failure') for n in range(6)])
    alerts = detect(events)
    assert 'AUTH-003' in alerts['rule_id'].tolist()
    assert 'AUTH-002' not in alerts['rule_id'].tolist()


def test_success_after_failures_same_ip_and_username(events_factory):
    specs = [(f'10:0{n}:00', '203.0.113.9', 'ana', 'failure') for n in range(3)]
    specs += [('10:03:00', '203.0.113.9', 'ana', 'success')]
    alerts = detect(events_factory(specs))
    assert 'AUTH-004' in alerts['rule_id'].tolist()
    specs[-1] = ('10:03:00', '203.0.113.8', 'ana', 'success')
    assert 'AUTH-004' not in detect(events_factory(specs))['rule_id'].tolist()


def test_offhours_timezone_is_explicit(events_factory):
    events = events_factory([('03:00:00', '203.0.113.10', 'ana', 'success')])
    assert detect(events).empty
    alerts = detect(events, DetectionConfig(detect_offhours=True, timezone='Europe/Madrid'))
    assert alerts.iloc[0]['rule_id'] == 'AUTH-005'


def test_bad_config_is_rejected(events_factory):
    with pytest.raises(ValueError):
        detect(events_factory([('10:00:00','10.0.0.2','ana','failure')]), DetectionConfig(window_minutes=0))


def test_evidence_ids_exist_and_cooldown(events_factory):
    events = events_factory([(f'10:00:{n:02d}', '203.0.113.8', 'ana', 'failure') for n in range(20)])
    alerts = detect(events)
    assert len(alerts[alerts['rule_id']=='AUTH-001']) == 1
    known = set(events['event_id'])
    for evidence in alerts['evidence_ids']:
        assert set(evidence).issubset(known)
