"""Agents, versions, identities — PRD §12–15, §44."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import (
    AgentKind,
    AgentStatus,
    Environment,
    FailMode,
    Framework,
    TrustLevel,
)


class Agent(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("organization_id", "name", "environment"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[AgentKind] = enum_column(AgentKind, nullable=False, default=AgentKind.ai_agent)
    framework: Mapped[Framework] = enum_column(Framework, nullable=False, default=Framework.custom)
    model: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[Environment] = enum_column(
        Environment, nullable=False, default=Environment.development
    )
    owner_team: Mapped[str | None] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[AgentStatus] = enum_column(
        AgentStatus, nullable=False, default=AgentStatus.healthy
    )
    risk_score: Mapped[int | None] = mapped_column(Integer)  # 0–100, PRD §11
    fail_mode: Mapped[FailMode] = enum_column(
        FailMode, nullable=False, default=FailMode.fail_closed
    )
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    external_ref: Mapped[str | None] = mapped_column(String(200))
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_versions.id", ondelete="SET NULL", use_alter=True)
    )

    versions: Mapped[list[AgentVersion]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
        foreign_keys="AgentVersion.agent_id",
    )
    identity: Mapped[AgentIdentity | None] = relationship(
        back_populates="agent", cascade="all, delete-orphan", uselist=False
    )


class AgentVersion(UUIDMixin, Base):
    __tablename__ = "agent_versions"
    __table_args__ = (UniqueConstraint("agent_id", "version"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(40), nullable=False)  # e.g. "1.8.2"
    model: Mapped[str | None] = mapped_column(String(120))
    system_prompt_hash: Mapped[str | None] = mapped_column(String(64))  # sha-256, PRD §75
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    source: Mapped[str | None] = mapped_column(String(200))  # git sha / deploy ref
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    agent: Mapped[Agent] = relationship(back_populates="versions", foreign_keys=[agent_id])


class AgentIdentity(UUIDMixin, TimestampMixin, Base):
    """PRD §15 — every agent gets an identity, trust level, owner, environment."""

    __tablename__ = "agent_identities"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), unique=True
    )
    identity: Mapped[str] = mapped_column(
        String(200), nullable=False, unique=True
    )  # agent:finance-prod
    trust_level: Mapped[TrustLevel] = enum_column(
        TrustLevel, nullable=False, default=TrustLevel.standard
    )
    owner: Mapped[str | None] = mapped_column(String(160))
    environment: Mapped[Environment] = enum_column(
        Environment, nullable=False, default=Environment.development
    )
    credentials_ref: Mapped[str | None] = mapped_column(String(255))  # pointer to secret store

    agent: Mapped[Agent] = relationship(back_populates="identity")
