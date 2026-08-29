"""Auth endpoints — /v1/auth/*."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

import jwt
from fastapi import APIRouter, Request, Response, status
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from .. import audit_log, regions
from ..config import get_settings
from ..models import ExternalIdentity, Organization, Session, User
from ..models.enums import ActorType
from ..security import hash_token, new_totp_secret, totp_provisioning_uri, verify_totp
from . import oauth, service
from .dependencies import CurrentPrincipal, CurrentUser, DbSession
from .schemas import (
    LoginRequest,
    LogoutRequest,
    MembershipOut,
    MeResponse,
    MfaChallengeResponse,
    MfaCodeRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    RefreshRequest,
    RegisterRequest,
    SessionOut,
    TokenResponse,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _meta(request: Request) -> service.RequestMeta:
    return service.RequestMeta(
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )


def _mfa_token(user_id: uuid.UUID, org_id: uuid.UUID | None) -> str:
    s = get_settings()
    now = int(time.time())
    return jwt.encode(
        {
            "sub": str(user_id),
            "org": str(org_id) if org_id else None,
            "typ": "mfa",
            "iat": now,
            "exp": now + 300,
        },
        s.secret_key,
        algorithm=s.jwt_algorithm,
    )


def _read_mfa_token(token: str) -> tuple[uuid.UUID, uuid.UUID | None]:
    s = get_settings()
    try:
        payload = jwt.decode(token, s.secret_key, algorithms=[s.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid mfa token") from exc
    if payload.get("typ") != "mfa":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
    org = payload.get("org")
    return uuid.UUID(payload["sub"]), (uuid.UUID(org) if org else None)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, db: DbSession) -> TokenResponse:
    if not get_settings().allow_open_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "open registration is disabled")
    if body.region is not None:
        regions.assert_servable(body.region)  # 421 → sign up at the right regional URL
    try:
        user, org, _ = await service.register(
            db,
            email=body.email,
            password=body.password,
            full_name=body.full_name,
            org_name=body.organization_name,
        )
    except service.AuthError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    sess, refresh_plain = await service.create_session(
        db, user=user, organization_id=org.id, meta=_meta(request), mfa_satisfied=True
    )
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)


@router.post("/login", responses={200: {"model": TokenResponse}})
async def login(
    body: LoginRequest, request: Request, db: DbSession
) -> TokenResponse | MfaChallengeResponse:
    try:
        user = await service.authenticate(db, email=body.email, password=body.password)
    except service.AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    membership = await service.resolve_membership(db, user, body.organization_id)
    org_id = membership.organization_id if membership else None
    user.last_login_at = datetime.now(UTC)

    if user.mfa_enabled and user.mfa_secret:
        return MfaChallengeResponse(mfa_token=_mfa_token(user.id, org_id))

    sess, refresh_plain = await service.create_session(
        db, user=user, organization_id=org_id, meta=_meta(request), mfa_satisfied=True
    )
    if org_id is not None:
        await audit_log.record(
            db,
            organization_id=org_id,
            action="auth.login",
            actor_type=ActorType.user,
            user_id=user.id,
            actor_label=user.email,
        )
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, request: Request, db: DbSession) -> TokenResponse:
    try:
        user, sess, refresh_plain = await service.rotate(
            db, refresh_token=body.refresh_token, meta=_meta(request)
        )
    except service.AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: LogoutRequest, principal: CurrentPrincipal, db: DbSession) -> Response:
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "not a user session")

    if body.all_sessions:
        await service.revoke_all_for_user(db, principal.user_id)
    else:
        target: Session | None = None
        if body.refresh_token:
            target = await db.scalar(
                select(Session).where(Session.refresh_token_hash == hash_token(body.refresh_token))
            )
        elif principal.session_id:
            target = await db.get(Session, principal.session_id)
        if target is not None and target.user_id == principal.user_id:
            await service.revoke_session(db, target)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeResponse)
async def me(principal: CurrentPrincipal, user: CurrentUser, db: DbSession) -> MeResponse:
    members = await service.memberships_for(db, user)
    out: list[MembershipOut] = []
    active_region = None
    for m in members:
        org = await db.get(Organization, m.organization_id)
        out.append(
            MembershipOut(
                organization_id=m.organization_id,
                organization_name=org.name if org else "",
                role=m.role,
                region=org.region if org else None,
            )
        )
        if org is not None and m.organization_id == principal.organization_id:
            active_region = org.region
    return MeResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        mfa_enabled=user.mfa_enabled,
        is_superuser=user.is_superuser,
        active_organization_id=principal.organization_id,
        active_region=active_region,
        region=regions.current_region(),
        permissions=sorted(principal.permissions),
        memberships=out,
    )


@router.get("/sessions", response_model=list[SessionOut])
async def list_sessions(
    principal: CurrentPrincipal, user: CurrentUser, db: DbSession
) -> list[SessionOut]:
    rows = (
        await db.scalars(
            select(Session)
            .where(Session.user_id == user.id, Session.revoked_at.is_(None))
            .order_by(Session.last_seen_at.desc())
        )
    ).all()
    return [
        SessionOut(
            id=r.id,
            user_agent=r.user_agent,
            ip_address=str(r.ip_address) if r.ip_address else None,
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            expires_at=r.expires_at,
            current=(r.id == principal.session_id),
        )
        for r in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_one(session_id: uuid.UUID, user: CurrentUser, db: DbSession) -> Response:
    target = await db.get(Session, session_id)
    if target is None or target.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    await service.revoke_session(db, target, reason="revoked_by_user")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- MFA (TOTP) -------------------------------------------------------------


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(user: CurrentUser) -> MfaEnrollResponse:
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA already enabled")
    secret = new_totp_secret()
    user.mfa_secret = secret  # pending until activated
    return MfaEnrollResponse(secret=secret, otpauth_uri=totp_provisioning_uri(secret, user.email))


@router.post("/mfa/activate", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_activate(body: MfaCodeRequest, user: CurrentUser) -> Response:
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "call /mfa/enroll first")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = True
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify(body: MfaVerifyRequest, request: Request, db: DbSession) -> TokenResponse:
    user_id, org_id = _read_mfa_token(body.mfa_token)
    user = await db.get(User, user_id)
    if user is None or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA not set up")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    sess, refresh_plain = await service.create_session(
        db, user=user, organization_id=org_id, meta=_meta(request), mfa_satisfied=True
    )
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(body: MfaCodeRequest, user: CurrentUser) -> Response:
    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enabled")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Organization switch ---------------------------------------------------


@router.post("/organizations/{organization_id}/switch", response_model=TokenResponse)
async def switch_org(
    organization_id: uuid.UUID,
    request: Request,
    principal: CurrentPrincipal,
    user: CurrentUser,
    db: DbSession,
) -> TokenResponse:
    membership = await service.resolve_membership(db, user, organization_id)
    if membership is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of that organization")
    sess, refresh_plain = await service.create_session(
        db,
        user=user,
        organization_id=organization_id,
        meta=_meta(request),
        mfa_satisfied=not principal.mfa_pending,
    )
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)


# --- OAuth ---------------------------------------------------------------


@router.get("/oauth/providers")
async def oauth_providers() -> dict:
    return {"providers": oauth.available_providers()}


@router.get("/oauth/{provider}/authorize")
async def oauth_authorize(
    provider: str, organization_id: uuid.UUID | None = None
) -> RedirectResponse:
    try:
        url = oauth.authorization_url(provider, str(organization_id) if organization_id else None)
    except oauth.OAuthError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/oauth/{provider}/callback", response_model=TokenResponse)
async def oauth_callback(
    provider: str,
    request: Request,
    db: DbSession,
    code: str | None = None,
    state: str | None = None,
) -> TokenResponse:
    if not code or not state:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing code/state")
    try:
        st = oauth.read_state(state)
        if st.get("provider") != provider:
            raise oauth.OAuthError("state/provider mismatch")
        profile = await oauth.exchange_code(provider, code)
    except oauth.OAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    identity = await db.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.provider == provider,
            ExternalIdentity.subject == profile.subject,
        )
    )
    if identity is not None:
        user = await db.get(User, identity.user_id)
    else:
        user = None
        if profile.email:
            user = await db.scalar(select(User).where(User.email == profile.email))
        if user is None:
            user = User(
                email=profile.email or f"{provider}:{profile.subject}",
                full_name=profile.full_name,
            )
            db.add(user)
            await db.flush()
        db.add(
            ExternalIdentity(
                user_id=user.id,
                provider=provider,
                subject=profile.subject,
                email=profile.email,
                raw_profile=profile.raw,
            )
        )
        await db.flush()

    assert user is not None
    org_val = st.get("org")
    membership = await service.resolve_membership(db, user, uuid.UUID(org_val) if org_val else None)
    org_id = membership.organization_id if membership else None
    sess, refresh_plain = await service.create_session(
        db, user=user, organization_id=org_id, meta=_meta(request), mfa_satisfied=True
    )
    return service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)
