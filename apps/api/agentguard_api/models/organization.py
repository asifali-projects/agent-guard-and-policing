"""Tenants, identity, RBAC, credentials — PRD §44 (organizations, users,
memberships, roles, permissions), §49–52."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import ApiKeyType, Environment, MembershipRole


class Organization(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    region: Mapped[str] = mapped_column(String(20), nullable=False, default="us")
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    full_name: Mapped[str | None] = mapped_column(String(200))
    # Null for SSO-only users (PRD §9, §51). Passwords are never handled in plain text.
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # TOTP shared secret (base32). Must be encrypted at rest in production — PRD §75.
    mfa_secret: Mapped[str | None] = mapped_column(String(64))
    last_login_at: Mapped[datetime | None] = mapped_column()

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="Membership.user_id",
    )


class Membership(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[MembershipRole] = enum_column(MembershipRole, nullable=False)
    invited_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])


role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(UUIDMixin, Base):
    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(
        String(80), nullable=False, unique=True
    )  # e.g. "policy.write"
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))


class Role(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    # Null organization_id == a built-in system role (PRD §50).
    organization_id: Mapped[uuid.UUID | None] = org_column(nullable=True)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions)


class ServiceAccount(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "service_accounts"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))


class ApiKey(UUIDMixin, TimestampMixin, Base):
    """PRD §52 — keys per environment, typed, scoped, rotatable, revocable."""

    __tablename__ = "api_keys"

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(24), nullable=False)  # e.g. "ag_live_"
    hashed_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    key_type: Mapped[ApiKeyType] = enum_column(ApiKeyType, nullable=False)
    environment: Mapped[Environment] = enum_column(Environment, nullable=False)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    ip_allowlist: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    last_used_at: Mapped[datetime | None] = mapped_column()
    expires_at: Mapped[datetime | None] = mapped_column()
    revoked_at: Mapped[datetime | None] = mapped_column()
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
