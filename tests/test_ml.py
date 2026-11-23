from pathlib import Path

import pytest

from sentinelai.ml import build_feature_matrix, detect_anomalies
from sentinelai.parsers import parse_bytes

ROOT = Path(__file__).resolve().parents[1]


def test_feature_matrix_and_isolation_forest():
    pytest.importorskip('sklearn')
    events = parse_bytes((ROOT / 'data/demo_auth.csv').read_bytes(), 'csv').events
    matrix = build_feature_matrix(events)
    assert len(matrix) >= 20
    result = detect_anomalies(events)
    assert len(result) == len(matrix)
    assert result['is_anomaly'].sum() > 0
    assert result['anomaly_score'].notna().all()


def test_invalid_contamination():
    with pytest.raises(ValueError):
        detect_anomalies(parse_bytes((ROOT / 'data/demo_auth.csv').read_bytes(), 'csv').events, contamination=.5)
