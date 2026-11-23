"""Optional experimental Isolation Forest, explicitly separated from rule alerts.

The model is fitted to the uploaded batch itself (unsupervised, no ground truth).
Anomalous means statistically unusual *within that batch*, not malicious.
"""

from __future__ import annotations

import pandas as pd

FEATURES = ("events", "failures", "unique_accounts", "failure_ratio", "after_hours")


def build_feature_matrix(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame(columns=["source_ip", "bucket", *FEATURES])
    data = events.copy()
    data["bucket"] = data["timestamp"].dt.floor("15min")
    data["failed"] = data["outcome"].eq("failure").astype(int)
    data["night"] = data["timestamp"].dt.hour.lt(6).astype(int)
    stats = data.groupby(["source_ip", "bucket"], as_index=False).agg(
        events=("event_id", "size"),
        failures=("failed", "sum"),
        unique_accounts=("username", "nunique"),
        after_hours=("night", "sum"),
    )
    stats["failure_ratio"] = stats["failures"] / stats["events"]
    return stats[["source_ip", "bucket", *FEATURES]]


def detect_anomalies(events: pd.DataFrame, *, contamination: float = 0.05) -> pd.DataFrame:
    """Return up to all source/time buckets, with score and anomaly flag.

    Requires at least 20 distinct source/time buckets. No model is persisted,
    and no data is sent off the machine.
    """
    if not 0 < contamination <= 0.25:
        raise ValueError("contamination debe estar entre 0 y 0.25")
    features = build_feature_matrix(events)
    if len(features) < 20:
        return pd.DataFrame(columns=[*features.columns, "anomaly_score", "is_anomaly"])
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    x = features[list(FEATURES)]
    model.fit(x)
    features = features.copy()
    # Larger anomaly_score means stranger; it's NOT a probability.
    features["anomaly_score"] = -model.decision_function(x)
    features["is_anomaly"] = model.predict(x) == -1
    return features.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
