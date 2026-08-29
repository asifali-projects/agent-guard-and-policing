"""Tool inventory — PRD §16, §44 (tools, tool_versions, agent_tools)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import RiskSeverity


class Tool(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tools"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(160), nullable=False)  # e.g. "payment.create"
    display_name: Mapped[str | None] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    owner_team: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str | None] = mapped_column(String(200))
    risk: Mapped[RiskSeverity] = enum_column(RiskSeverity, nullable=False, default=RiskSeverity.low)
    permissions: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )  # PermissionScope[]
    data_access: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    destination: Mapped[str | None] = mapped_column(String(200))

    versions: Mapped[list[ToolVersion]] = relationship(
        back_populates="tool", cascade="all, delete-orphan"
    )


class ToolVersion(UUIDMixin, Base):
    __tablename__ = "tool_versions"
    __table_args__ = (UniqueConstraint("tool_id", "version"),)

    tool_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tools.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    parameters_schema: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    tool: Mapped[Tool] = relationship(back_populates="versions")


class AgentTool(UUIDMixin, TimestampMixin, Base):
    """Which tools an agent may call, and with what grant (PRD §13 Permissions tab)."""

    __tablename__ = "agent_tools"
    __table_args__ = (UniqueConstraint("agent_id", "tool_id"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tools.id", ondelete="CASCADE"), index=True
    )
    granted_permissions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column()
