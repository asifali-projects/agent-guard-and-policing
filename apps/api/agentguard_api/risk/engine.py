"""The 7-factor risk computation (PRD §26)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..dlp.service import DlpResult
from ..models import Agent, AgentIdentity, AuditEvent, RedTeamFinding, Tool
from ..models.enums import (
    AgentStatus,
    Decision,
    FindingStatus,
    PermissionScope,
    RiskSeverity,
    TrustLevel,
)
from .schemas import RiskAssessment, RiskFactor

WEIGHTS: dict[str, float] = {
    "identity": 0.15,
    "permission": 0.12,
    "tool": 0.18,
    "data": 0.22,
    "destination": 0.13,
    "behavior": 0.10,
    "historical": 0.10,
}

_TRUST_RISK = {
    TrustLevel.untrusted: 95,
    TrustLevel.low: 72,
    TrustLevel.standard: 42,
    TrustLevel.high: 20,
    TrustLevel.privileged: 10,
}
_STATUS_BUMP = {
    AgentStatus.critical: 25,
    AgentStatus.high: 15,
    AgentStatus.warning: 8,
    AgentStatus.paused: 30,
}
_TOOL_RISK = {
    RiskSeverity.info: 5,
    RiskSeverity.low: 18,
    RiskSeverity.medium: 45,
    RiskSeverity.high: 72,
    RiskSeverity.critical: 92,
}
_SCOPE_RISK = {
    PermissionScope.read: 12,
    PermissionScope.write: 55,
    PermissionScope.execute: 65,
    PermissionScope.admin: 92,
}
_DATA_RISK = {"public": 5, "internal": 22, "confidential": 66, "restricted": 90}


def _clamp(v: float) -> int:
    return max(0, min(100, round(v)))


def _identity_factor(agent: Agent, identity: AgentIdentity | None) -> RiskFactor:
    trust = identity.trust_level if identity else TrustLevel.standard
    score = _TRUST_RISK[trust] + _STATUS_BUMP.get(agent.status, 0)
    return RiskFactor(
        name="identity",
        score=_clamp(score),
        weight=WEIGHTS["identity"],
        detail=f"trust={trust.value}, status={agent.status.value}",
    )


def _permission_factor(tool: Tool | None) -> RiskFactor:
    if tool is None or not tool.permissions:
        return RiskFactor(
            name="permission", score=30, weight=WEIGHTS["permission"], detail="tool not inventoried"
        )
    valid = {s.value for s in PermissionScope}
    scopes = [PermissionScope(p) for p in tool.permissions if p in valid]
    top = max((_SCOPE_RISK[s] for s in scopes), default=20)
    return RiskFactor(
        name="permission",
        score=_clamp(top),
        weight=WEIGHTS["permission"],
        detail=f"scopes={[s.value for s in scopes] or tool.permissions}",
    )


def _tool_factor(tool: Tool | None, tool_name: str) -> RiskFactor:
    if tool is None:
        return RiskFactor(
            name="tool", score=35, weight=WEIGHTS["tool"], detail=f"'{tool_name}' not inventoried"
        )
    return RiskFactor(
        name="tool",
        score=_TOOL_RISK[tool.risk],
        weight=WEIGHTS["tool"],
        detail=f"risk={tool.risk.value}",
    )


def _data_factor(dlp: DlpResult) -> RiskFactor:
    if dlp.classification is None:
        return RiskFactor(name="data", score=5, weight=WEIGHTS["data"], detail="no sensitive data")
    base = _DATA_RISK[dlp.classification.value]
    if dlp.has_never_exfil:
        base = max(base, 96)
    detectors = sorted({f.detector for f in dlp.findings})
    return RiskFactor(
        name="data",
        score=_clamp(base),
        weight=WEIGHTS["data"],
        detail=f"class={dlp.classification.value}, detectors={detectors}",
    )


def _destination_factor(context: dict) -> RiskFactor:
    dest = str(context.get("destination") or context.get("destination_url") or "").lower()
    if not dest:
        return RiskFactor(
            name="destination", score=35, weight=WEIGHTS["destination"], detail="unspecified"
        )
    if dest in {"internal", "internal-api", "same-tenant"}:
        score = 10
    elif dest in {"external", "public", "third-party"} or "://" in dest:
        score = 82
    else:
        score = 45
    return RiskFactor(
        name="destination", score=score, weight=WEIGHTS["destination"], detail=f"destination={dest}"
    )


def _behavior_factor(anomaly_score: int, signals: list[str]) -> RiskFactor:
    """Deviation from the agent's learned baseline (PRD §28)."""
    return RiskFactor(
        name="behavior",
        score=_clamp(anomaly_score),
        weight=WEIGHTS["behavior"],
        detail=signals[0] if signals else "consistent with baseline",
    )


async def _historical_factor(
    session: AsyncSession, organization_id: uuid.UUID, agent_id: uuid.UUID
) -> RiskFactor:
    open_findings = await session.scalar(
        select(func.count())
        .select_from(RedTeamFinding)
        .where(
            RedTeamFinding.agent_id == agent_id,
            RedTeamFinding.status.in_(
                [FindingStatus.open, FindingStatus.triaged, FindingStatus.retest]
            ),
            RedTeamFinding.severity.in_([RiskSeverity.high, RiskSeverity.critical]),
        )
    )
    since = datetime.now(UTC) - timedelta(hours=24)
    recent_denies = await session.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(
            AuditEvent.organization_id == organization_id,
            AuditEvent.agent_id == agent_id,
            AuditEvent.decision == Decision.deny,
            AuditEvent.occurred_at >= since,
        )
    )
    score = min(100, (open_findings or 0) * 22 + (recent_denies or 0) * 12)
    return RiskFactor(
        name="historical",
        score=_clamp(score),
        weight=WEIGHTS["historical"],
        detail=f"open hi/crit findings={open_findings or 0}, denies/24h={recent_denies or 0}",
    )


def _severity(score: int) -> RiskSeverity:
    if score >= 85:
        return RiskSeverity.critical
    if score >= 65:
        return RiskSeverity.high
    if score >= 40:
        return RiskSeverity.medium
    if score >= 20:
        return RiskSeverity.low
    return RiskSeverity.info


def _decision(severity: RiskSeverity) -> str:
    if severity == RiskSeverity.critical:
        return "BLOCK"
    if severity == RiskSeverity.high:
        return "APPROVAL"
    return "ALLOW"


async def assess(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    agent: Agent,
    identity: AgentIdentity | None,
    tool: Tool | None,
    tool_name: str,
    parameters: dict,
    context: dict,
    dlp: DlpResult,
    anomaly_score: int = 10,
    anomaly_signals: list[str] | None = None,
) -> RiskAssessment:
    factors = [
        _identity_factor(agent, identity),
        _permission_factor(tool),
        _tool_factor(tool, tool_name),
        _data_factor(dlp),
        _destination_factor(context or {}),
        _behavior_factor(anomaly_score, anomaly_signals or []),
        await _historical_factor(session, organization_id, agent.id),
    ]
    score = _clamp(sum(f.score * f.weight for f in factors))
    # A severe behavioural anomaly is inherently high-risk regardless of the
    # other factors (PRD §28 — "Behavioral anomaly — risk 94").
    if anomaly_score >= 90:
        score = max(score, 82)
    elif anomaly_score >= 75:
        score = max(score, 66)
    severity = _severity(score)
    return RiskAssessment(
        risk_score=score, severity=severity, decision=_decision(severity), factors=factors
    )
