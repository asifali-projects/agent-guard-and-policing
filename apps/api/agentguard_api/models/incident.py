"""Threats + incident response — PRD §28, §30, §44 (threats, incidents,
incident_events)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import ActorType, IncidentStatus, RiskSeverity, ThreatStatus


class Threat(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "threats"

    organization_id: Mapped[uuid.UUID] = org_column()
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(
        String(80), nullable=False
    )  # e.g. "indirect_prompt_injection"
    severity: Mapped[RiskSeverity] = enum_column(RiskSeverity, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[ThreatStatus] = enum_column(
        ThreatStatus, nullable=False, default=ThreatStatus.open
    )
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(80))  # detection engine / rule id
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )


class Incident(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    key: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. "INC-2043"
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    severity: Mapped[RiskSeverity] = enum_column(RiskSeverity, nullable=False)
    status: Mapped[IncidentStatus] = enum_column(
        IncidentStatus, nullable=False, default=IncidentStatus.detected
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"))
    opened_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    summary: Mapped[str | None] = mapped_column(Text)
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    contained_at: Mapped[datetime | None] = mapped_column()
    resolved_at: Mapped[datetime | None] = mapped_column()
    closed_at: Mapped[datetime | None] = mapped_column()

    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )


class IncidentEvent(UUIDMixin, Base):
    """Timeline entry — status change or automatic response action (PRD §30)."""

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(60), nullable=False)  # status_change / action / note
    actor_type: Mapped[ActorType] = enum_column(ActorType, nullable=False, default=ActorType.system)
    actor_id: Mapped[str | None] = mapped_column(String(200))
    message: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    incident: Mapped[Incident] = relationship(back_populates="events")
