"""Human approval — PRD §29, §44 (approval_requests, approval_decisions)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import ApprovalDecisionType, ApprovalStatus, RiskSeverity


class ApprovalRequest(UUIDMixin, TimestampMixin, Base):
    """An approval is bound to the exact action, exact parameters, identity,
    expiration and approver (PRD §29)."""

    __tablename__ = "approval_requests"

    organization_id: Mapped[uuid.UUID] = org_column()
    request_id: Mapped[str] = mapped_column(
        String(80), nullable=False, unique=True
    )  # runtime correlation
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tools.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    parameters_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[RiskSeverity] = enum_column(
        RiskSeverity, nullable=False, default=RiskSeverity.medium
    )
    reason: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ApprovalStatus] = enum_column(
        ApprovalStatus, nullable=False, default=ApprovalStatus.pending
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column()
    decided_at: Mapped[datetime | None] = mapped_column()

    decisions: Mapped[list[ApprovalDecision]] = relationship(
        back_populates="request", cascade="all, delete-orphan"
    )


class ApprovalDecision(UUIDMixin, Base):
    __tablename__ = "approval_decisions"

    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_requests.id", ondelete="CASCADE"), index=True
    )
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[ApprovalDecisionType] = enum_column(ApprovalDecisionType, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    request: Mapped[ApprovalRequest] = relationship(back_populates="decisions")
