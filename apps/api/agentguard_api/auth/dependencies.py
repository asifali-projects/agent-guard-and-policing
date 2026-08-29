"""FastAPI dependencies: resolve the request principal and enforce permissions.

A request authenticates either as a **user** (JWT access token, acting inside
one organization) or as an **API key** (PRD §52). Both resolve to a `Principal`
carrying an organization id and a permission set.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, Request, status
from fastapi.exceptions import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import ApiKey, Membership, Organization, Session, User
from ..models.enums import ActorType
from ..rbac import permissions_for_role
from ..regions import assert_servable
from ..security import decode_access_token
from ..security.api_keys import parse_api_key, verify_secret
from ..security.tokens import TokenError

DbSession = Annotated[AsyncSession, Depends(get_session)]


@dataclass
class Principal:
    kind: str  # "user" | "api_key"
    organization_id: uuid.UUID | None
    permissions: frozenset[str]
    actor_type: ActorType
    actor_label: str
    user_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None
    mfa_pending: bool = False
    scopes: list[str] = field(default_factory=list)

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token else None


async def _principal_from_jwt(token: str, db: AsyncSession, request: Request) -> Principal:
    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {exc}") from exc

    session_id = payload["sid"]
    sess = await db.get(Session, uuid.UUID(session_id))
    if sess is None or sess.revoked_at is not None or sess.expires_at <= datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired or revoked")

    user = await db.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account disabled")

    sess.last_seen_at = datetime.now(UTC)

    org_id = sess.organization_id
    permissions: frozenset[str] = frozenset()
    if org_id is not None:
        membership = await db.scalar(
            select(Membership).where(
                Membership.user_id == user.id, Membership.organization_id == org_id
            )
        )
        if membership is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of this organization")
        permissions = permissions_for_role(membership.role)

    mfa_pending = user.mfa_enabled and not sess.mfa_satisfied

    return Principal(
        kind="user",
        organization_id=org_id,
        permissions=permissions if not mfa_pending else frozenset(),
        actor_type=ActorType.user,
        actor_label=user.email,
        user_id=user.id,
        session_id=sess.id,
        mfa_pending=mfa_pending,
    )


async def _principal_from_api_key(raw: str, db: AsyncSession, request: Request) -> Principal:
    parts = parse_api_key(raw)
    if parts is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "malformed API key")

    key = await db.scalar(select(ApiKey).where(ApiKey.prefix == parts.prefix))
    if key is None or not verify_secret(parts.secret, key.hashed_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
    now = datetime.now(UTC)
    if key.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key revoked")
    if key.expires_at is not None and key.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key expired")

    client_ip = request.client.host if request.client else None
    if key.ip_allowlist and client_ip not in set(key.ip_allowlist):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "source IP not allowed for this key")

    key.last_used_at = now
    key.usage_count += 1

    scopes = list(key.scopes or [])
    permissions = frozenset(scopes) if scopes else frozenset({"runtime.evaluate"})

    return Principal(
        kind="api_key",
        organization_id=key.organization_id,
        permissions=permissions,
        actor_type=ActorType.service_account,
        actor_label=f"apikey:{key.prefix}",
        api_key_id=key.id,
        scopes=scopes,
    )


async def get_principal(
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Principal:
    token = _bearer(authorization)
    raw_key = x_api_key or (token if token and token.startswith("ag_") else None)

    if raw_key:
        principal = await _principal_from_api_key(raw_key, db, request)
    elif token:
        principal = await _principal_from_jwt(token, db, request)
    else:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Data residency: this deployment only serves its own region (PRD §76).
    if principal.organization_id is not None:
        org = await db.get(Organization, principal.organization_id)
        if org is not None:
            assert_servable(org.region)

    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


async def get_current_user(principal: CurrentPrincipal, db: DbSession) -> User:
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "endpoint requires a user session")
    user = await db.get(User, principal.user_id)
    assert user is not None
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(*needed: str):
    async def _dep(principal: CurrentPrincipal) -> Principal:
        if principal.mfa_pending:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_required")
        if principal.organization_id is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "no active organization")
        missing = [p for p in needed if not principal.has(p)]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"missing permission(s): {', '.join(missing)}"
            )
        return principal

    return _dep


async def require_org(principal: CurrentPrincipal) -> uuid.UUID:
    if principal.organization_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no active organization")
    return principal.organization_id


CurrentOrgId = Annotated[uuid.UUID, Depends(require_org)]


async def load_org(org_id: CurrentOrgId, db: DbSession) -> Organization:
    org = await db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return org


CurrentOrg = Annotated[Organization, Depends(load_org)]
