"""Auth business logic: registration, login, session rotation + revocation."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..config import get_settings
from ..models import Membership, Organization, Session, User
from ..models.enums import ActorType, MembershipRole
from ..security import (
    hash_password,
    hash_token,
    needs_rehash,
    new_access_token,
    new_opaque_token,
    verify_password,
)
from .schemas import TokenResponse


class AuthError(Exception):
    """Authentication or session error (maps to 401)."""


@dataclass(frozen=True)
class RequestMeta:
    user_agent: str | None = None
    ip_address: str | None = None


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:70] or "org"


async def unique_slug(session: AsyncSession, name: str) -> str:
    base = _slugify(name)
    slug = base
    n = 1
    while await session.scalar(select(Organization.id).where(Organization.slug == slug)):
        n += 1
        slug = f"{base}-{n}"
    return slug


async def register(
    session: AsyncSession, *, email: str, password: str, full_name: str | None, org_name: str
) -> tuple[User, Organization, Membership]:
    email = email.strip().lower()
    exists = await session.scalar(select(User.id).where(func.lower(User.email) == email))
    if exists:
        raise AuthError("email already registered")

    user = User(email=email, full_name=full_name, hashed_password=hash_password(password))
    org = Organization(name=org_name.strip(), slug=await unique_slug(session, org_name))
    session.add_all([user, org])
    await session.flush()

    membership = Membership(organization_id=org.id, user_id=user.id, role=MembershipRole.owner)
    session.add(membership)
    await session.flush()

    await audit_log.record(
        session,
        organization_id=org.id,
        action="auth.register",
        actor_type=ActorType.user,
        user_id=user.id,
        actor_label=email,
        metadata={"organization_name": org.name},
    )
    return user, org, membership


async def authenticate(session: AsyncSession, *, email: str, password: str) -> User:
    user = await session.scalar(select(User).where(func.lower(User.email) == email.strip().lower()))
    if user is None or not user.hashed_password or not user.is_active:
        raise AuthError("invalid credentials")
    if not verify_password(password, user.hashed_password):
        raise AuthError("invalid credentials")
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)
    return user


async def memberships_for(session: AsyncSession, user: User) -> list[Membership]:
    return list(
        (await session.scalars(select(Membership).where(Membership.user_id == user.id))).all()
    )


async def resolve_membership(
    session: AsyncSession, user: User, organization_id: uuid.UUID | None
) -> Membership | None:
    members = await memberships_for(session, user)
    if not members:
        return None
    if organization_id is None:
        return members[0]
    return next((m for m in members if m.organization_id == organization_id), None)


async def create_session(
    session: AsyncSession,
    *,
    user: User,
    organization_id: uuid.UUID | None,
    meta: RequestMeta,
    mfa_satisfied: bool,
    previous_session_id: uuid.UUID | None = None,
) -> tuple[Session, str]:
    settings = get_settings()
    refresh_plain, refresh_hash = new_opaque_token()
    sess = Session(
        user_id=user.id,
        organization_id=organization_id,
        refresh_token_hash=refresh_hash,
        previous_session_id=previous_session_id,
        user_agent=(meta.user_agent or "")[:400] or None,
        ip_address=meta.ip_address,
        mfa_satisfied=mfa_satisfied,
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.refresh_token_ttl_seconds),
    )
    session.add(sess)
    await session.flush()
    return sess, refresh_plain


def issue_tokens(*, user: User, sess: Session, refresh_plain: str) -> TokenResponse:
    settings = get_settings()
    access = new_access_token(
        subject=str(user.id),
        organization_id=str(sess.organization_id) if sess.organization_id else None,
        session_id=str(sess.id),
        extra={"mfa": sess.mfa_satisfied},
    )
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_plain,
        expires_in=settings.access_token_ttl_seconds,
        organization_id=sess.organization_id,
    )


async def rotate(
    session: AsyncSession, *, refresh_token: str, meta: RequestMeta
) -> tuple[User, Session, str]:
    token_hash = hash_token(refresh_token)
    sess = await session.scalar(select(Session).where(Session.refresh_token_hash == token_hash))
    if sess is None:
        raise AuthError("invalid refresh token")

    now = datetime.now(UTC)
    if sess.revoked_at is not None:
        # Reuse of an already-rotated token: revoke the whole family. This must
        # persist even though the request fails, so commit before raising.
        await _revoke_family(session, sess, reason="reuse_detected")
        await session.commit()
        raise AuthError("refresh token reuse detected")
    if sess.expires_at <= now:
        raise AuthError("refresh token expired")

    user = await session.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise AuthError("account disabled")

    sess.revoked_at = now
    sess.revoked_reason = "rotated"
    new_sess, refresh_plain = await create_session(
        session,
        user=user,
        organization_id=sess.organization_id,
        meta=meta,
        mfa_satisfied=sess.mfa_satisfied,
        previous_session_id=sess.id,
    )
    return user, new_sess, refresh_plain


async def _revoke_family(session: AsyncSession, sess: Session, *, reason: str) -> None:
    seen: set[uuid.UUID] = set()
    cursor: Session | None = sess
    while cursor and cursor.id not in seen:
        seen.add(cursor.id)
        cursor.revoked_at = cursor.revoked_at or datetime.now(UTC)
        cursor.revoked_reason = reason
        cursor = await session.scalar(
            select(Session).where(Session.previous_session_id == cursor.id)
        )
    # also revoke any live sibling sessions for the user
    for other in (
        await session.scalars(
            select(Session).where(Session.user_id == sess.user_id, Session.revoked_at.is_(None))
        )
    ).all():
        other.revoked_at = datetime.now(UTC)
        other.revoked_reason = reason


async def revoke_session(session: AsyncSession, sess: Session, *, reason: str = "logout") -> None:
    if sess.revoked_at is None:
        sess.revoked_at = datetime.now(UTC)
        sess.revoked_reason = reason


async def revoke_all_for_user(
    session: AsyncSession, user_id: uuid.UUID, *, reason: str = "logout_all"
) -> int:
    rows = (
        await session.scalars(
            select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
        )
    ).all()
    for row in rows:
        row.revoked_at = datetime.now(UTC)
        row.revoked_reason = reason
    return len(rows)
