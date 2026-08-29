"""MCP server + tool inventory — PRD §17, §44 (mcp_servers, mcp_tools)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import McpServerStatus, RiskSeverity


class McpServer(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "mcp_servers"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(160), nullable=False)  # e.g. "Postgres MCP"
    url: Mapped[str | None] = mapped_column(String(400))
    owner_team: Mapped[str | None] = mapped_column(String(120))
    version: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[McpServerStatus] = enum_column(
        McpServerStatus, nullable=False, default=McpServerStatus.review_required
    )
    risk: Mapped[RiskSeverity] = enum_column(
        RiskSeverity, nullable=False, default=RiskSeverity.medium
    )
    trusted: Mapped[bool] = mapped_column(nullable=False, default=False)
    external_dependencies: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    last_scan_at: Mapped[datetime | None] = mapped_column()
    # Latest scan check results: tool poisoning, malicious metadata, excessive
    # permissions, credential exposure, unexpected network, dangerous fs (PRD §17).
    scan_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    tools: Mapped[list[McpTool]] = relationship(
        back_populates="server", cascade="all, delete-orphan"
    )


class McpTool(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "mcp_tools"
    __table_args__ = (UniqueConstraint("mcp_server_id", "name"),)

    mcp_server_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("mcp_servers.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    permissions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    risk: Mapped[RiskSeverity] = enum_column(RiskSeverity, nullable=False, default=RiskSeverity.low)
    metadata_flags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    server: Mapped[McpServer] = relationship(back_populates="tools")
