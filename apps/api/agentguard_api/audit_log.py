"""Append-only, tamper-evident audit log (PRD §33).

Each organization's events form a SHA-256 hash chain: every row's ``entry_hash``
covers the previous row's ``entry_hash`` plus this row's canonical content. A
per-organization advisory lock serialises writers so the chain stays linear.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent
from .models.enums import ActorType, Decision

GENESIS = "0" * 64


def _canonical(fields: dict[str, Any]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


async def record(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    action: str,
    actor_type: ActorType,
    actor_id: str | None = None,
    actor_label: str | None = None,
    user_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
    agent_version: str | None = None,
    tool: str | None = None,
    policy_key: str | None = None,
    decision: Decision | None = None,
    risk_score: int | None = None,
    trace_id: str | None = None,
    request_id: str | None = None,
    payload_hash: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(organization_id)}
    )

    prev = (
        await session.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(1)
        )
    ).first()
    prev_hash = prev.entry_hash if prev else GENESIS
    resolved_actor_id = actor_id or actor_label

    content = {
        "organization_id": organization_id,
        "action": action,
        "actor_type": actor_type.value,
        "actor_id": resolved_actor_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "agent_version": agent_version,
        "tool": tool,
        "policy_key": policy_key,
        "decision": decision.value if decision else None,
        "risk_score": risk_score,
        "trace_id": trace_id,
        "request_id": request_id,
        "payload_hash": payload_hash,
        "metadata": metadata or {},
    }
    entry_hash = hashlib.sha256(f"{prev_hash}{_canonical(content)}".encode()).hexdigest()

    event = AuditEvent(
        organization_id=organization_id,
        action=action,
        actor_type=actor_type,
        actor_id=resolved_actor_id,
        user_id=user_id,
        agent_id=agent_id,
        agent_version=agent_version,
        tool=tool,
        policy_key=policy_key,
        decision=decision,
        risk_score=risk_score,
        trace_id=trace_id,
        request_id=request_id,
        payload_hash=payload_hash,
        metadata_=metadata or {},
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(event)
    await session.flush()
    return event


async def verify_chain(session: AsyncSession, organization_id: uuid.UUID) -> bool:
    """Recompute the chain for one org; return True if intact."""
    rows = (
        await session.scalars(
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
        )
    ).all()
    prev_hash = GENESIS
    for row in rows:
        content = {
            "organization_id": row.organization_id,
            "action": row.action,
            "actor_type": row.actor_type.value,
            "actor_id": row.actor_id,
            "user_id": row.user_id,
            "agent_id": row.agent_id,
            "agent_version": row.agent_version,
            "tool": row.tool,
            "policy_key": row.policy_key,
            "decision": row.decision.value if row.decision else None,
            "risk_score": row.risk_score,
            "trace_id": row.trace_id,
            "request_id": row.request_id,
            "payload_hash": row.payload_hash,
            "metadata": row.metadata_,
        }
        expected = hashlib.sha256(f"{prev_hash}{_canonical(content)}".encode()).hexdigest()
        if row.prev_hash != prev_hash or row.entry_hash != expected:
            return False
        prev_hash = row.entry_hash
    return True
