from __future__ import annotations

import pandas as pd
import pytest

from sentinelai.parsers import normalize


@pytest.fixture
def events_factory():
    def make(specs):
        records = []
        for when, ip, user, outcome in specs:
            records.append({"timestamp": f"2026-11-20T{when}Z", "source_ip": ip, "username": user, "outcome": outcome, "service": "ssh"})
        return normalize(pd.DataFrame.from_records(records)).events
    return make
