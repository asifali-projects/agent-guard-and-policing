"""Risk engine — the multi-factor score on the runtime critical path (PRD §26).

    Identity + Permission + Tool + Data + Destination + Behavior + Historical
      -> { risk_score, severity, decision }

Kept lightweight and deterministic. The behavioral factor is a heuristic here;
Step 8 replaces it with real per-agent baselines.
"""

from .engine import assess
from .schemas import RiskAssessment, RiskFactor

__all__ = ["RiskAssessment", "RiskFactor", "assess"]
