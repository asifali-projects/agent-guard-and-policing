"""Enterprise SSO connections — PRD §9, §51.

One row per configured identity provider for an organization. Client secrets and
SAML private keys live in `config` and must be encrypted at rest in production
(same wrapping story as `users.mfa_secret`).
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import MembershipRole, SsoProtocol


class SsoConnection(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "sso_connections"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = org_column()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    protocol: Mapped[SsoProtocol] = enum_column(SsoProtocol, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # When enforced, members whose email matches a domain here cannot use a password.
    enforced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    domains: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    default_role: Mapped[MembershipRole] = enum_column(
        MembershipRole, nullable=False, default=MembershipRole.developer
    )
    # OIDC: issuer / client_id / client_secret / *_endpoint / jwks_uri / scopes
    # SAML: idp_entity_id / idp_sso_url / idp_x509_cert / sp_private_key / sp_cert
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
