"""DLP / data security — PRD §27, §44 (data_classifications, data_policies)."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import DataClassification, DlpAction


class DataClassificationRule(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "data_classifications"
    __table_args__ = (UniqueConstraint("organization_id", "label"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    label: Mapped[DataClassification] = enum_column(DataClassification, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Detector set: PII, credentials, API keys, tokens, financial, health, source code, secrets.
    detectors: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class DataPolicy(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "data_policies"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    classification: Mapped[DataClassification] = enum_column(DataClassification, nullable=False)
    action: Mapped[DlpAction] = enum_column(DlpAction, nullable=False, default=DlpAction.redact)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Scope: which agents / tools / destinations this applies to.
    applies_to: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
