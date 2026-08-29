"""Sessions + external identities — PRD §51 (session rotation, revocation,
device tracking) and §9 (OAuth sign-in)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class Session(UUIDMixin, TimestampMixin, Base):
    """One row per active refresh token. Rotated on every refresh."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # The org the session is currently acting in (switchable without re-login).
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Chain of rotated tokens for reuse detection.
    previous_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL")
    )
    user_agent: Mapped[str | None] = mapped_column(String(400))
    ip_address: Mapped[str | None] = mapped_column(INET)
    mfa_satisfied: Mapped[bool] = mapped_column(nullable=False, default=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(60))


class ExternalIdentity(UUIDMixin, TimestampMixin, Base):
    """Links a user to an OAuth / OIDC provider account (PRD §9)."""

    __tablename__ = "external_identities"
    __table_args__ = (UniqueConstraint("provider", "subject"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(
        String(40), nullable=False
    )  # google | microsoft | oidc:<id>
    subject: Mapped[str] = mapped_column(String(255), nullable=False)  # provider's stable user id
    email: Mapped[str | None] = mapped_column(String(320))
    raw_profile: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
