"""Judge one observed decision against a technique's expected security behaviour."""

from __future__ import annotations

from dataclasses import dataclass

from agentguard_policy import Decision

from ..models.enums import RiskSeverity
from ..runtime.core import CoreDecision
from .catalog import Technique

_SEV_ORDER = [
    RiskSeverity.info,
    RiskSeverity.low,
    RiskSeverity.medium,
    RiskSeverity.high,
    RiskSeverity.critical,
]


@dataclass(frozen=True)
class Verdict:
    passed: bool
    severity: RiskSeverity
    expected_behavior: str
    observed_behavior: str
    recommendation: str


def _max_sev(a: RiskSeverity, b: RiskSeverity) -> RiskSeverity:
    return a if _SEV_ORDER.index(a) >= _SEV_ORDER.index(b) else b


def judge(technique: Technique, decision: Decision, core: CoreDecision) -> Verdict:
    passed = decision in technique.defended
    expected = f"one of {sorted(d.value.upper() for d in technique.defended)}"
    risk = core.risk.risk_score if core.risk else 0
    observed = f"decision={decision.value.upper()} · risk={risk}"
    if core.reasons:
        observed += f" · {core.reasons[0]}"

    if passed:
        return Verdict(True, RiskSeverity.info, expected, observed, "No action needed.")

    severity = technique.base_severity
    if core.risk is not None:
        severity = _max_sev(severity, core.risk.severity)
    return Verdict(False, severity, expected, observed, technique.recommendation)
