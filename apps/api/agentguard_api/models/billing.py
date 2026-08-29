"""Billing + usage metering — PRD §64–65, §44 (subscriptions, plans,
usage_records, invoices)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import InvoiceStatus, PlanCode, SubscriptionStatus, UsageMetric


class Plan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "plans"

    code: Mapped[PlanCode] = enum_column(PlanCode, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    monthly_price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="usd")
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # {"agents": 10, "runtime_actions": 100000, "redteam_runs": 20, ...}
    limits: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class Subscription(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "subscriptions"

    organization_id: Mapped[uuid.UUID] = org_column()
    plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("plans.id"), index=True)
    status: Mapped[SubscriptionStatus] = enum_column(
        SubscriptionStatus, nullable=False, default=SubscriptionStatus.trialing
    )
    current_period_start: Mapped[datetime | None] = mapped_column()
    current_period_end: Mapped[datetime | None] = mapped_column()
    external_customer_ref: Mapped[str | None] = mapped_column(String(120))
    external_subscription_ref: Mapped[str | None] = mapped_column(String(120))

    invoices: Mapped[list[Invoice]] = relationship(back_populates="subscription")


class UsageRecord(UUIDMixin, Base):
    """Metered usage per PRD §65."""

    __tablename__ = "usage_records"

    organization_id: Mapped[uuid.UUID] = org_column()
    metric: Mapped[UsageMetric] = enum_column(UsageMetric, nullable=False)
    quantity: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Invoice(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "invoices"

    organization_id: Mapped[uuid.UUID] = org_column()
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="SET NULL")
    )
    number: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    amount_due_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="usd")
    status: Mapped[InvoiceStatus] = enum_column(
        InvoiceStatus, nullable=False, default=InvoiceStatus.draft
    )
    period_start: Mapped[datetime | None] = mapped_column()
    period_end: Mapped[datetime | None] = mapped_column()
    issued_at: Mapped[datetime | None] = mapped_column()
    paid_at: Mapped[datetime | None] = mapped_column()
    external_ref: Mapped[str | None] = mapped_column(String(120))

    subscription: Mapped[Subscription | None] = relationship(back_populates="invoices")
