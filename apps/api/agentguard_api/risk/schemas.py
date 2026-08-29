"""Risk engine output models."""

from __future__ import annotations

from pydantic import BaseModel

from ..models.enums import RiskSeverity


class RiskFactor(BaseModel):
    name: str
    score: int  # 0–100
    weight: float
    detail: str


class RiskAssessment(BaseModel):
    risk_score: int
    severity: RiskSeverity
    decision: str  # ALLOW | APPROVAL | BLOCK  (PRD §26 output)
    factors: list[RiskFactor]

    def factor(self, name: str) -> RiskFactor | None:
        return next((f for f in self.factors if f.name == name), None)
