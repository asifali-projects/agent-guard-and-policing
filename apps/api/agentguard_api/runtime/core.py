"""The side-effect-free heart of a runtime decision (PRD §24–27).

`core_decision` runs DLP -> policy engine -> risk engine and combines them. It
performs **no writes** (no approval rows, no audit, no telemetry, no rate-limit
counter). `evaluate_runtime` wraps it with the stateful steps; the red-team
sandbox calls it directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from agentguard_policy import Decision, EvaluationInput, RateLimitSpec, evaluate
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..detection.anomaly import AnomalyResult, score_anomaly
from ..detection.profile import as_dict, load_profile
from ..dlp.service import DlpResult, scan_payload
from ..models import Agent, AgentIdentity, Tool
from ..models.enums import AgentStatus, DlpAction, RiskSeverity
from ..risk import RiskAssessment
from ..risk import assess as assess_risk
from ..risk.schemas import RiskFactor
from .loader import load_policy_set

_PRECEDENCE = (
    Decision.deny,
    Decision.approval,
    Decision.rate_limit,
    Decision.redact,
    Decision.allow,
)


@dataclass
class CoreDecision:
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    policy_keys: list[str] = field(default_factory=list)
    rate_limit_spec: RateLimitSpec | None = None
    classification: str | None = None
    cache_hit: bool = False
    risk: RiskAssessment | None = None
    dlp: DlpResult | None = None
    anomaly: AnomalyResult | None = None
    agent: Agent | None = None
    identity: AgentIdentity | None = None
    tool: Tool | None = None


def combine(
    policy_decision: Decision,
    policy_reasons: list[str],
    dlp: DlpResult,
    risk_decision: str,
    risk_score: int,
) -> tuple[Decision, list[str]]:
    candidates: list[tuple[Decision, str]] = [
        (policy_decision, policy_reasons[0] if policy_reasons else "policy")
    ]
    if dlp.action == DlpAction.block:
        candidates.append((Decision.deny, f"DLP: {dlp.classification.value} data blocked"))
    elif dlp.action == DlpAction.approval:
        candidates.append(
            (Decision.approval, f"DLP: {dlp.classification.value} data needs approval")
        )
    elif dlp.action == DlpAction.redact:
        candidates.append((Decision.redact, f"DLP: redacting {dlp.classification.value} data"))

    if risk_decision == "BLOCK":
        candidates.append((Decision.deny, f"risk score {risk_score} (critical)"))
    elif risk_decision == "APPROVAL":
        candidates.append((Decision.approval, f"risk score {risk_score} (high)"))

    present = {d for d, _ in candidates}
    final = next((lvl for lvl in _PRECEDENCE if lvl in present), Decision.allow)

    reasons = list(policy_reasons)
    for d, r in candidates:
        if d == final and r not in reasons:
            reasons.append(r)
    return final, reasons


async def core_decision(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    agent: Agent,
    tool: str,
    action: str = "execute",
    parameters: dict | None = None,
    context: dict | None = None,
    data_classification: str | None = None,
) -> CoreDecision:
    parameters = parameters or {}
    context = context or {}

    identity = await session.scalar(select(AgentIdentity).where(AgentIdentity.agent_id == agent.id))
    tool_row = await session.scalar(
        select(Tool).where(Tool.organization_id == organization_id, Tool.name == tool)
    )
    environment = agent.environment.value

    dlp = await scan_payload(session, organization_id, parameters)
    classification = dlp.classification.value if dlp.classification else data_classification

    profile = await load_profile(session, agent.id)
    anomaly = score_anomaly(
        as_dict(profile),
        tool=tool,
        parameters=parameters,
        context=context,
        classification=classification,
    )

    # A paused agent is denied everything (incident response — PRD §30).
    if agent.status == AgentStatus.paused:
        return CoreDecision(
            decision=Decision.deny,
            reasons=["agent is paused"],
            classification=classification,
            dlp=dlp,
            anomaly=anomaly,
            risk=RiskAssessment(
                risk_score=100,
                severity=RiskSeverity.critical,
                decision="BLOCK",
                factors=[
                    RiskFactor(
                        name="identity",
                        score=100,
                        weight=1.0,
                        detail="agent is paused by incident response",
                    )
                ],
            ),
            agent=agent,
            identity=identity,
            tool=tool_row,
        )

    policies, cache_hit = await load_policy_set(
        session,
        organization_id=organization_id,
        environment=environment,
        agent_id=agent.id,
        tool_name=tool,
        action=action,
    )
    policy_result = evaluate(
        EvaluationInput(
            tool=tool,
            action=action,
            environment=environment,
            agent_id=str(agent.id),
            agent_trust_level=identity.trust_level.value if identity else None,
            parameters=parameters,
            context=context,
            data_classification=classification,
        ),
        policies,
    )

    risk = await assess_risk(
        session,
        organization_id=organization_id,
        agent=agent,
        identity=identity,
        tool=tool_row,
        tool_name=tool,
        parameters=parameters,
        context=context,
        dlp=dlp,
        anomaly_score=anomaly.score,
        anomaly_signals=anomaly.signals,
    )

    decision, reasons = combine(
        policy_result.decision, policy_result.reasons, dlp, risk.decision, risk.risk_score
    )

    redactions = list(policy_result.redactions)
    if decision == Decision.redact or dlp.action == DlpAction.redact:
        for path in dlp.redaction_paths:
            if path not in redactions:
                redactions.append(path)

    return CoreDecision(
        decision=decision,
        reasons=reasons,
        redactions=redactions,
        policy_keys=policy_result.matched_policy_keys,
        rate_limit_spec=policy_result.rate_limit,
        classification=classification,
        cache_hit=cache_hit,
        risk=risk,
        dlp=dlp,
        anomaly=anomaly,
        agent=agent,
        identity=identity,
        tool=tool_row,
    )
