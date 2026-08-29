"""SSO connection lookup + just-in-time user provisioning (PRD §9, §51)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..models import ExternalIdentity, Membership, SsoConnection, User
from ..models.enums import ActorType


def _domain(email: str) -> str:
    return email.strip().rsplit("@", 1)[-1].lower()


def _provider_key(conn: SsoConnection) -> str:
    return f"sso:{conn.id}"


async def _match(session: AsyncSession, email: str, *, enforced_only: bool) -> SsoConnection | None:
    domain = _domain(email)
    if not domain or "@" not in email:
        return None
    stmt = select(SsoConnection).where(SsoConnection.enabled.is_(True))
    if enforced_only:
        stmt = stmt.where(SsoConnection.enforced.is_(True))
    for conn in (await session.scalars(stmt)).all():
        if domain in {str(d).lower() for d in (conn.domains or [])}:
            return conn
    return None


async def connection_for_email(session: AsyncSession, email: str) -> SsoConnection | None:
    """The enabled SSO connection that owns this email's domain, if any."""
    return await _match(session, email, enforced_only=False)


async def enforced_for_email(session: AsyncSession, email: str) -> SsoConnection | None:
    """As above, but only when the connection forbids password login for the domain."""
    return await _match(session, email, enforced_only=True)


async def provision(
    session: AsyncSession,
    *,
    conn: SsoConnection,
    subject: str,
    email: str | None,
    name: str | None,
    raw: dict,
) -> User:
    """Resolve (or create) the local user for an authenticated SSO subject.

    Links the subject to a stable `ExternalIdentity`, creates the user on first
    sign-in, and ensures a membership in the connection's organization with the
    connection's default role.
    """
    provider = _provider_key(conn)
    email = (email or "").strip().lower() or None

    identity = await session.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.provider == provider,
            ExternalIdentity.subject == subject,
        )
    )
    user: User | None = None
    if identity is not None:
        user = await session.get(User, identity.user_id)

    if user is None and email:
        user = await session.scalar(select(User).where(User.email == email))

    created = False
    if user is None:
        if not email:
            raise ValueError("SSO profile has no email and no known identity")
        user = User(email=email, full_name=name, hashed_password=None)
        session.add(user)
        await session.flush()
        created = True
    elif name and not user.full_name:
        user.full_name = name

    if identity is None:
        session.add(
            ExternalIdentity(
                user_id=user.id,
                provider=provider,
                subject=subject,
                email=email,
                raw_profile=raw,
            )
        )
    else:
        identity.email = email or identity.email
        identity.raw_profile = raw

    membership = await session.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == conn.organization_id,
        )
    )
    if membership is None:
        session.add(
            Membership(
                organization_id=conn.organization_id,
                user_id=user.id,
                role=conn.default_role,
            )
        )

    await session.flush()
    await audit_log.record(
        session,
        organization_id=conn.organization_id,
        action="auth.sso_login",
        actor_type=ActorType.user,
        user_id=user.id,
        actor_label=user.email,
        metadata={
            "connection": conn.name,
            "protocol": conn.protocol.value,
            "provisioned": created,
        },
    )
    return user
