"""Runtime evaluation orchestration (PRD §24–25)."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

from agentguard_policy import Decision, EvaluationInput, evaluate
from fastapi import status
from fastapi.exceptions import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..auth.dependencies import Principal
from ..models import Agent, ApprovalRequest, Tool
from ..models.enums import Decision as DbDecision
from ..models.enums import RiskSeverity
from .emit import emit_decision
from .loader import load_policy_set
from .ratelimit import check_and_consume
from .schemas import RateLimitOut, RuntimeEvaluateRequest, RuntimeEvaluateResponse

_APPROVAL_TTL = timedelta(hours=1)
_RISK_BASE = {
    RiskSeverity.info: 5,
    RiskSeverity.low: 15,
    RiskSeverity.medium: 40,
    RiskSeverity.high: 70,
    RiskSeverity.critical: 92,
}
_RISK_FLOOR = {
    Decision.deny: 80,
    Decision.approval: 60,
    Decision.rate_limit: 45,
    Decision.redact: 40,
    Decision.allow: 0,
}


def _params_hash(parameters: dict) -> str:
    canon = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def _risk_score(tool: Tool | None, decision: Decision) -> int:
    base = _RISK_BASE[tool.risk] if tool is not None else 20
    return max(0, min(100, max(base, _RISK_FLOOR.get(decision, 0))))


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

    environment = agent.environment.value
    tool = await session.scalar(
        select(Tool).where(Tool.organization_id == principal.organization_id, Tool.name == req.tool)
    )

    policies, cache_hit = await load_policy_set(
        session,
        organization_id=principal.organization_id,
        environment=environment,
        agent_id=req.agent_id,
        tool_name=req.tool,
        action=req.action,
    )

    result = evaluate(
        EvaluationInput(
            tool=req.tool,
            action=req.action,
            environment=environment,
            agent_id=str(req.agent_id),
            parameters=req.parameters,
            context=req.context,
            data_classification=req.data_classification,
        ),
        policies,
    )

    decision = result.decision
    risk = _risk_score(tool, decision)
    approval_id: uuid.UUID | None = None
    rate_out: RateLimitOut | None = None
    reasons = list(result.reasons)

    if decision == Decision.rate_limit and result.rate_limit is not None:
        verdict = await check_and_consume(
            org_id=principal.organization_id,
            agent_id=req.agent_id,
            tool=req.tool,
            spec=result.rate_limit,
        )
        rate_out = RateLimitOut(
            max=result.rate_limit.max,
            window_seconds=result.rate_limit.window_seconds,
            scope=result.rate_limit.scope,
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
            tool_id=tool.id if tool else None,
            params_hash=_params_hash(req.parameters),
            request_id=request_id,
            risk_score=risk,
            reason=reasons[0] if reasons else "approval required",
        )
        if decision == Decision.allow:
            reasons.append("matching approval already granted")

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    policy_keys = result.matched_policy_keys
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
            "risk_score": risk,
            "policy_key": policy_keys[0] if policy_keys else "",
            "latency_ms": elapsed_ms,
            "cache_hit": 1 if cache_hit else 0,
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
            policy_key=policy_keys[0] if policy_keys else None,
            decision=DbDecision(decision.value),
            risk_score=risk,
            request_id=request_id,
            payload_hash=_params_hash(req.parameters),
        )

    return RuntimeEvaluateResponse(
        decision=decision.value.upper(),
        risk_score=risk,
        request_id=request_id,
        policy_id=policy_keys[0] if policy_keys else None,
        policy_keys=policy_keys,
        reasons=reasons,
        redactions=result.redactions,
        approval_request_id=approval_id,
        rate_limit=rate_out,
        fail_mode=fail_mode,
        cache_hit=cache_hit,
        evaluated_in_ms=elapsed_ms,
    )
