"""Audit log — PRD §33.

Append-only and tamper-evident: each row carries the hash of the previous row
for its organization, forming a hash chain. Rows are never updated or deleted by
the application.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UUIDMixin, enum_column, org_column
from .enums import ActorType, Decision


class AuditEvent(UUIDMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_org_occurred", "organization_id", "occurred_at"),
        Index("ix_audit_events_trace_id", "trace_id"),
    )

    organization_id: Mapped[uuid.UUID] = org_column()
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    actor_type: Mapped[ActorType] = enum_column(ActorType, nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(200))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"))
    agent_version: Mapped[str | None] = mapped_column(String(40))

    tool: Mapped[str | None] = mapped_column(String(160))
    action: Mapped[str | None] = mapped_column(String(120))
    policy_key: Mapped[str | None] = mapped_column(String(40))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    decision: Mapped[Decision | None] = enum_column(Decision, nullable=True)

    trace_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(80))

    # Data minimisation (PRD §75): store a hash, not the payload.
    payload_hash: Mapped[str | None] = mapped_column(String(64))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    # Hash chain.
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
