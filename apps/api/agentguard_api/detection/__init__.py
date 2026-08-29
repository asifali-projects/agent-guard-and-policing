"""Behavioral detection (PRD §28).

`anomaly.score_anomaly` is pure; `profile` loads and updates the per-agent
baseline. Runs on the runtime path today; ClickHouse-backed baselines move to a
worker later.
"""

from .anomaly import AnomalyResult, score_anomaly
from .profile import load_profile, observe

__all__ = ["AnomalyResult", "load_profile", "observe", "score_anomaly"]
