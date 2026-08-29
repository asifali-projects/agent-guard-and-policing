"""Policy engine storage — PRD §23, §44 (policies, policy_versions,
policy_bindings)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import Environment, PolicyScopeType


class Policy(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    key: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. "FIN-004"
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # Rule body: deny / allow / approval lists + conditions (PRD §23).
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )
    bindings: Mapped[list[PolicyBinding]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyVersion(UUIDMixin, Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)

    policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    policy: Mapped[Policy] = relationship(back_populates="versions")


class PolicyBinding(UUIDMixin, TimestampMixin, Base):
    """Attaches a policy at a level of the hierarchy: org → env → agent → tool → action."""

    __tablename__ = "policy_bindings"

    organization_id: Mapped[uuid.UUID] = org_column()
    policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), index=True
    )
    scope_type: Mapped[PolicyScopeType] = enum_column(PolicyScopeType, nullable=False)
    environment: Mapped[Environment | None] = enum_column(Environment, nullable=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    tool_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tools.id", ondelete="CASCADE"))
    action: Mapped[str | None] = mapped_column(String(120))

    policy: Mapped[Policy] = relationship(back_populates="bindings")
