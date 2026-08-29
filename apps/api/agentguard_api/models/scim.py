"""SCIM 2.0 provisioning state — PRD §51.

One `ScimConfig` per organization holds the IdP's bearer token (hashed). Provisioned
principals live in `scim_users` / `scim_groups`; the actual access grant is still a
plain `memberships` row, created and removed as the IdP activates/deactivates the
user. Group membership drives the effective role.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import MembershipRole


class ScimConfig(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scim_configs"
    __table_args__ = (UniqueConstraint("organization_id"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # sha-256 of the bearer token the IdP sends; the plaintext is shown once.
    token_hash: Mapped[str | None] = mapped_column(String(64))
    # Role for provisioned users not matched by any mapped group.
    default_role: Mapped[MembershipRole] = enum_column(
        MembershipRole, nullable=False, default=MembershipRole.developer
    )
    last_request_at: Mapped[datetime | None] = mapped_column()


class ScimUser(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scim_users"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
        UniqueConstraint("organization_id", "user_name"),
    )

    organization_id: Mapped[uuid.UUID] = org_column()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str | None] = mapped_column(String(255), index=True)
    user_name: Mapped[str] = mapped_column(String(320), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    deprovisioned_at: Mapped[datetime | None] = mapped_column()


class ScimGroup(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scim_groups"
    __table_args__ = (UniqueConstraint("organization_id", "display_name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255), index=True)
    # Set when `display_name` resolves to a built-in role (see scim.roles).
    mapped_role: Mapped[MembershipRole | None] = enum_column(MembershipRole, nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class ScimGroupMember(Base):
    __tablename__ = "scim_group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scim_groups.id", ondelete="CASCADE"), primary_key=True
    )
    scim_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scim_users.id", ondelete="CASCADE"), primary_key=True
    )
