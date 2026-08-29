"""Integrations + webhooks — PRD §17 (webhooks), §43, §62, §44."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import IntegrationCategory


class Integration(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "provider"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    provider: Mapped[str] = mapped_column(
        String(60), nullable=False
    )  # okta, splunk, github, slack…
    category: Mapped[IntegrationCategory] = enum_column(IntegrationCategory, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="connected")
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)  # non-secret
    secret_ref: Mapped[str | None] = mapped_column(String(255))  # pointer to secret store
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))


class Webhook(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "webhooks"

    organization_id: Mapped[uuid.UUID] = org_column()
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    events: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # PRD §43 event names
    secret_hash: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_delivery_at: Mapped[datetime | None] = mapped_column()
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
