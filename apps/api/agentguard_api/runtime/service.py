"""Runtime evaluation orchestration (PRD §24–27).

core_decision (side-effect free)  ->  rate-limit consume  ->  approval  ->  emit + audit
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

from agentguard_policy import Decision
from fastapi import status
from fastapi.exceptions import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..auth.dependencies import Principal
from ..detection import profile
from ..incidents import service as incidents
from ..models import Agent, ApprovalRequest
from ..models.enums import Decision as DbDecision
from ..models.enums import RiskSeverity
from .core import core_decision
from .emit import emit_decision
from .ratelimit import check_and_consume
from .schemas import RateLimitOut, RuntimeEvaluateRequest, RuntimeEvaluateResponse

_APPROVAL_TTL = timedelta(hours=1)


def _params_hash(parameters: dict) -> str:
    canon = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


async def _resolve_approval(
    session: AsyncSession,
    *,
    principal: Principal,
    req: RuntimeEvaluateRequest,
    tool_id: uuid.UUID | None,
    params_hash: str,
    request_id: str,
    risk_score: int,
    reason: str,
) -> tuple[Decision, uuid.UUID | None]:
    action_str = f"{req.tool}:{req.action}"
    now = datetime.now(UTC)

    base = select(ApprovalRequest).where(
        ApprovalRequest.organization_id == principal.organization_id,
        ApprovalRequest.agent_id == req.agent_id,
        ApprovalRequest.action == action_str,
        ApprovalRequest.parameters_hash == params_hash,
    )
    approved = await session.scalar(base.where(ApprovalRequest.status == "approved"))
    if approved is not None and (approved.expires_at is None or approved.expires_at > now):
        return Decision.allow, approved.id

    pending = await session.scalar(base.where(ApprovalRequest.status == "pending"))
    if pending is not None and (pending.expires_at is None or pending.expires_at > now):
        return Decision.approval, pending.id

    fresh = ApprovalRequest(
        organization_id=principal.organization_id,
        request_id=request_id,
        agent_id=req.agent_id,
        tool_id=tool_id,
        action=action_str,
        parameters=req.parameters,
        parameters_hash=params_hash,
        risk_score=risk_score,
        severity=RiskSeverity.high if risk_score >= 70 else RiskSeverity.medium,
        reason=reason[:1000],
        status="pending",
        expires_at=now + _APPROVAL_TTL,
    )
    session.add(fresh)
    await session.flush()
    return Decision.approval, fresh.id


async def evaluate_runtime(
    session: AsyncSession, principal: Principal, req: RuntimeEvaluateRequest
) -> RuntimeEvaluateResponse:
    started = time.perf_counter()
    request_id = req.request_id or uuid.uuid4().hex

    agent = await session.get(Agent, req.agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")

    core = await core_decision(
        session,
        organization_id=principal.organization_id,
        agent=agent,
        tool=req.tool,
        action=req.action,
        parameters=req.parameters,
        context=req.context,
        data_classification=req.data_classification,
    )
    decision = core.decision
    reasons = list(core.reasons)
    risk = core.risk
    assert risk is not None

    approval_id: uuid.UUID | None = None
    rate_out: RateLimitOut | None = None

    if decision == Decision.rate_limit and core.rate_limit_spec is not None:
        verdict = await check_and_consume(
            org_id=principal.organization_id,
            agent_id=req.agent_id,
            tool=req.tool,
            spec=core.rate_limit_spec,
        )
        rate_out = RateLimitOut(
            max=core.rate_limit_spec.max,
            window_seconds=core.rate_limit_spec.window_seconds,
            scope=core.rate_limit_spec.scope,
            remaining=verdict.remaining,
            retry_after_seconds=None if verdict.allowed else verdict.retry_after_seconds,
        )
        if verdict.allowed:
            decision = Decision.allow
            reasons.append("within rate-limit budget")
        else:
            reasons.append("rate-limit budget exceeded")

    if decision == Decision.approval:
        decision, approval_id = await _resolve_approval(
            session,
            principal=principal,
            req=req,
            tool_id=core.tool.id if core.tool else None,
            params_hash=_params_hash(req.parameters),
            request_id=request_id,
            risk_score=risk.risk_score,
            reason=reasons[-1] if reasons else "approval required",
        )
        if decision == Decision.allow:
            reasons.append("matching approval already granted")

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    fail_mode = agent.fail_mode.value

    await emit_decision(
        {
            "event_id": str(uuid.uuid4()),
            "occurred_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "organization_id": str(principal.organization_id),
            "agent_id": str(req.agent_id),
            "tool": req.tool,
            "action": req.action,
            "decision": decision.value,
            "risk_score": risk.risk_score,
            "policy_key": core.policy_keys[0] if core.policy_keys else "",
            "latency_ms": elapsed_ms,
            "cache_hit": 1 if core.cache_hit else 0,
            "fail_mode": fail_mode,
            "trace_id": "",
            "request_id": request_id,
        }
    )

    if decision != Decision.allow:
        await audit_log.record(
            session,
            organization_id=principal.organization_id,
            action="runtime.evaluate",
            actor_type=principal.actor_type,
            actor_label=principal.actor_label,
            user_id=principal.user_id,
            agent_id=req.agent_id,
            tool=req.tool,
            policy_key=core.policy_keys[0] if core.policy_keys else None,
            decision=DbDecision(decision.value),
            risk_score=risk.risk_score,
            request_id=request_id,
            payload_hash=_params_hash(req.parameters),
            metadata={
                "classification": core.classification,
                "dlp_detectors": (
                    sorted({f.detector for f in core.dlp.findings}) if core.dlp else []
                ),
            },
        )

    # Learn from this call, then raise a threat if it deviated sharply.
    await profile.observe(
        session,
        organization_id=principal.organization_id,
        agent_id=req.agent_id,
        tool=req.tool,
        parameters=req.parameters,
        context=req.context,
        classification=core.classification,
        anomaly_score=core.anomaly.score if core.anomaly else 0,
    )
    if core.anomaly and core.anomaly.is_anomalous:
        await incidents.raise_behavioral_threat(
            session,
            organization_id=principal.organization_id,
            agent_id=req.agent_id,
            tool=req.tool,
            anomaly=core.anomaly,
            risk_score=risk.risk_score,
            request_id=request_id,
        )

    return RuntimeEvaluateResponse(
        decision=decision.value.upper(),
        risk_score=risk.risk_score,
        request_id=request_id,
        policy_id=core.policy_keys[0] if core.policy_keys else None,
        policy_keys=core.policy_keys,
        reasons=reasons,
        redactions=core.redactions,
        approval_request_id=approval_id,
        rate_limit=rate_out,
        fail_mode=fail_mode,
        cache_hit=core.cache_hit,
        evaluated_in_ms=elapsed_ms,
        risk_severity=risk.severity.value,
        data_classification=core.classification,
    )
