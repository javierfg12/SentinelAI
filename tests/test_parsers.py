import json

import pandas as pd
import pytest

from sentinelai.parsers import ParseError, normalize, parse_bytes


def test_csv_aliases_and_invalid_rows():
    data = b'time,src_ip,user,status\n2026-11-20T01:00:00Z,203.0.113.7,ana,ok\n2026-11-20T01:00:00Z,bad-ip,bob,fail\n'
    result = parse_bytes(data, 'csv')
    assert len(result.events) == 1
    assert result.dropped_rows == 1
    assert result.events.iloc[0]['outcome'] == 'success'
    assert str(result.events.iloc[0]['timestamp'].tz) == 'UTC'


def test_jsonl_and_ipv6():
    row = {'timestamp': '2026-11-20T07:25:00+01:00', 'source_ip': '2001:db8::4', 'username': 'admin', 'outcome': 'failure'}
    result = parse_bytes((json.dumps(row) + '\n').encode(), 'jsonl')
    assert len(result.events) == 1
    assert result.events.iloc[0]['timestamp'].hour == 6


def test_ssh_pattern_and_ignored_lines():
    content = b'Nov 20 09:11:00 lab sshd[100]: Failed password for invalid user guest from 203.0.113.2 port 555 ssh2\nNov 20 09:11:01 lab systemd[1]: Started service\nNov 20 09:13:01 lab sshd[101]: Accepted publickey for admin from 203.0.113.2 port 555 ssh2\n'
    result = parse_bytes(content, 'ssh', ssh_year=2026)
    assert len(result.events) == 2
    assert result.dropped_rows == 1
    assert set(result.events['outcome']) == {'failure', 'success'}
    assert result.events['timestamp'].dt.year.unique().tolist() == [2026]


def test_jsonl_rejects_invalid_lines():
    with pytest.raises(ParseError, match='línea 2'):
        parse_bytes(b'{"timestamp": 1}\n!\n', 'jsonl')


def test_rejects_incompatible_csv():
    with pytest.raises(ParseError, match='obligatorias'):
        parse_bytes(b'user,origin\nana,203.0.113.2\n', 'csv')


def test_rejects_oversize():
    with pytest.raises(ParseError, match='10 MB'):
        parse_bytes(b'x' * (10 * 1024 * 1024 + 1), 'csv')


def test_rejects_bad_utf8():
    with pytest.raises(ParseError, match='UTF-8'):
        parse_bytes(b'\xff\x01', 'csv')


def test_ids_are_stable_and_distinguish_duplicates():
    raw = pd.DataFrame([{'timestamp': '2026-11-20T00:00:00Z', 'source_ip': '203.0.113.3', 'username': 'ana', 'outcome': 'failure'}]*2)
    a, b = normalize(raw).events, normalize(raw).events
    assert a['event_id'].tolist() == b['event_id'].tolist()
    assert len(set(a['event_id'])) == 2
