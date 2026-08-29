"""AI Security Analyst conversations — PRD §35.

A conversation is a thread of natural-language questions and grounded answers.
Every answer records the read-only tools it called and the citations it used, so
the reasoning is auditable.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, org_column


class AnalystConversation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "analyst_conversations"

    organization_id: Mapped[uuid.UUID] = org_column()
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="New conversation")

    messages: Mapped[list[AnalystMessage]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AnalystMessage.created_at",
    )


class AnalystMessage(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "analyst_messages"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analyst_conversations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # user | assistant
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # [{"tool": "...", "arguments": {...}}]
    tool_calls: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # [{"tool": "...", "summary": "..."}]
    citations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # "claude" | "fallback"
    engine: Mapped[str | None] = mapped_column(String(16))

    conversation: Mapped[AnalystConversation] = relationship(back_populates="messages")
