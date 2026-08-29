"""Declarative base, naming conventions, and shared column mixins."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Deterministic constraint names so Alembic autogenerate produces stable diffs.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDMixin:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


def org_column(*, nullable: bool = False, ondelete: str = "CASCADE") -> Mapped[uuid.UUID]:
    """`organization_id` FK — every tenant-scoped table carries one (PRD §49)."""
    return mapped_column(
        ForeignKey("organizations.id", ondelete=ondelete),
        nullable=nullable,
        index=True,
    )


def enum_column(py_enum: type[enum.Enum], **kwargs: Any) -> Any:
    """A VARCHAR-backed enum column (values checked, no Postgres enum type)."""
    return mapped_column(
        Enum(py_enum, native_enum=False, length=48, validate_strings=True),
        **kwargs,
    )
