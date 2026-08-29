"""Approval endpoints — /v1/approvals (PRD §29).

An approval is bound to the exact action, exact parameters (hash), agent
identity, and an expiry. Approving one does not execute anything — the agent
re-calls `/v1/runtime/evaluate`, which now returns ALLOW for that exact request.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import ApprovalDecision, ApprovalRequest
from ..models.enums import ActorType, ApprovalStatus, Decision, RiskSeverity

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])

ReadDep = Annotated[Principal, Depends(require_permission("approval.read"))]
DecideDep = Annotated[Principal, Depends(require_permission("approval.decide"))]


class ApprovalOut(BaseModel):
    id: uuid.UUID
    request_id: str
    agent_id: uuid.UUID
    action: str
    parameters: dict
    parameters_hash: str
    risk_score: int | None
    severity: RiskSeverity
    reason: str | None
    status: ApprovalStatus
    requested_at: datetime
    expires_at: datetime | None
    decided_at: datetime | None


class DecisionIn(BaseModel):
    comment: str | None = Field(default=None, max_length=2000)


def _out(a: ApprovalRequest) -> ApprovalOut:
    return ApprovalOut(
        id=a.id,
        request_id=a.request_id,
        agent_id=a.agent_id,
        action=a.action,
        parameters=a.parameters,
        parameters_hash=a.parameters_hash,
        risk_score=a.risk_score,
        severity=a.severity,
        reason=a.reason,
        status=a.status,
        requested_at=a.requested_at,
        expires_at=a.expires_at,
        decided_at=a.decided_at,
    )


async def _load(db, principal: Principal, approval_id: uuid.UUID) -> ApprovalRequest:
    a = await db.get(ApprovalRequest, approval_id)
    if a is None or a.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found")
    return a


@router.get("", response_model=list[ApprovalOut])
async def list_approvals(
    db: DbSession,
    principal: ReadDep,
    status_filter: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
) -> list[ApprovalOut]:
    stmt = select(ApprovalRequest).where(
        ApprovalRequest.organization_id == principal.organization_id
    )
    if status_filter is not None:
        stmt = stmt.where(ApprovalRequest.status == status_filter)
    stmt = stmt.order_by(ApprovalRequest.requested_at.desc())
    return [_out(a) for a in (await db.scalars(stmt)).all()]


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_approval(approval_id: uuid.UUID, db: DbSession, principal: ReadDep) -> ApprovalOut:
    return _out(await _load(db, principal, approval_id))


async def _decide(
    db, principal: Principal, approval_id: uuid.UUID, *, approved: bool, comment: str | None
) -> ApprovalOut:
    a = await _load(db, principal, approval_id)
    now = datetime.now(UTC)
    if a.status != ApprovalStatus.pending:
        raise HTTPException(status.HTTP_409_CONFLICT, f"approval already {a.status.value}")
    if a.expires_at is not None and a.expires_at <= now:
        a.status = ApprovalStatus.expired
        raise HTTPException(status.HTTP_409_CONFLICT, "approval expired")

    a.status = ApprovalStatus.approved if approved else ApprovalStatus.rejected
    a.decided_at = now
    db.add(
        ApprovalDecision(
            approval_request_id=a.id,
            decided_by_id=principal.user_id,
            decision="approved" if approved else "rejected",
            comment=comment,
        )
    )
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="approval.approve" if approved else "approval.reject",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        agent_id=a.agent_id,
        decision=Decision.allow if approved else Decision.deny,
        risk_score=a.risk_score,
        request_id=a.request_id,
        payload_hash=a.parameters_hash,
    )
    return _out(a)


@router.post("/{approval_id}/approve", response_model=ApprovalOut)
async def approve(
    approval_id: uuid.UUID, body: DecisionIn, db: DbSession, principal: DecideDep
) -> ApprovalOut:
    return await _decide(db, principal, approval_id, approved=True, comment=body.comment)


@router.post("/{approval_id}/reject", response_model=ApprovalOut)
async def reject(
    approval_id: uuid.UUID, body: DecisionIn, db: DbSession, principal: DecideDep
) -> ApprovalOut:
    return await _decide(db, principal, approval_id, approved=False, comment=body.comment)
