"""Audit endpoints — /v1/audit (PRD §33: searchable, tamper-evident)."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, tuple_

from ..audit_log import verify_chain
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import AuditEvent
from ..models.enums import Decision

router = APIRouter(prefix="/v1/audit", tags=["audit"])

ReadDep = Annotated[Principal, Depends(require_permission("audit.read"))]


class AuditEventOut(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    action: str
    actor_type: str
    actor_id: str | None
    agent_id: uuid.UUID | None
    tool: str | None
    policy_key: str | None
    decision: Decision | None
    risk_score: int | None
    trace_id: str | None
    request_id: str | None
    entry_hash: str
    prev_hash: str | None


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_cursor: str | None = None


@router.get("/events", response_model=AuditPage)
async def list_events(
    db: DbSession,
    principal: ReadDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
    action: str | None = None,
    decision: Decision | None = None,
    agent_id: uuid.UUID | None = None,
    since: datetime | None = None,
) -> AuditPage:
    stmt = select(AuditEvent).where(AuditEvent.organization_id == principal.organization_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if decision:
        stmt = stmt.where(AuditEvent.decision == decision)
    if agent_id:
        stmt = stmt.where(AuditEvent.agent_id == agent_id)
    if since:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    if cursor:
        c_time, _, c_id = cursor.partition("|")
        stmt = stmt.where(
            tuple_(AuditEvent.occurred_at, AuditEvent.id)
            < (datetime.fromisoformat(c_time), uuid.UUID(c_id))
        )
    stmt = stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(limit + 1)

    rows = list((await db.scalars(stmt)).all())
    next_cursor = (
        f"{rows[limit].occurred_at.isoformat()}|{rows[limit].id}" if len(rows) > limit else None
    )
    rows = rows[:limit]
    return AuditPage(
        items=[
            AuditEventOut(
                id=r.id,
                occurred_at=r.occurred_at,
                action=r.action,
                actor_type=r.actor_type.value,
                actor_id=r.actor_id,
                agent_id=r.agent_id,
                tool=r.tool,
                policy_key=r.policy_key,
                decision=r.decision,
                risk_score=r.risk_score,
                trace_id=r.trace_id,
                request_id=r.request_id,
                entry_hash=r.entry_hash,
                prev_hash=r.prev_hash,
            )
            for r in rows
        ],
        next_cursor=next_cursor,
    )


_EXPORT_COLUMNS = [
    "occurred_at",
    "action",
    "actor_type",
    "actor_id",
    "agent_id",
    "agent_version",
    "tool",
    "action_verb",
    "policy_key",
    "risk_score",
    "decision",
    "trace_id",
    "request_id",
    "payload_hash",
    "prev_hash",
    "entry_hash",
]


@router.get("/events.csv")
async def export_events(
    db: DbSession,
    principal: ReadDep,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100_000)] = 10_000,
) -> StreamingResponse:
    stmt = select(AuditEvent).where(AuditEvent.organization_id == principal.organization_id)
    if since:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    stmt = stmt.order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc()).limit(limit)
    rows = list((await db.scalars(stmt)).all())

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_EXPORT_COLUMNS)
    for r in rows:
        w.writerow(
            [
                r.occurred_at.isoformat(),
                r.action,
                r.actor_type.value,
                r.actor_id or "",
                r.agent_id or "",
                r.agent_version or "",
                r.tool or "",
                r.action or "",
                r.policy_key or "",
                r.risk_score if r.risk_score is not None else "",
                r.decision.value if r.decision else "",
                r.trace_id or "",
                r.request_id or "",
                r.payload_hash or "",
                r.prev_hash or "",
                r.entry_hash,
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=agentguard-audit.csv"},
    )


class ChainStatus(BaseModel):
    intact: bool
    event_count: int = Field(description="events checked")


@router.get("/verify", response_model=ChainStatus)
async def verify(db: DbSession, principal: ReadDep) -> ChainStatus:
    count = await db.scalar(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.organization_id == principal.organization_id)
    )
    intact = await verify_chain(db, principal.organization_id)
    return ChainStatus(intact=intact, event_count=count or 0)
