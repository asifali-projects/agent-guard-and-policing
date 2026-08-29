"""Enterprise SSO endpoints (PRD §9, §51).

Two surfaces:

* ``/v1/auth/sso/*`` — the unauthenticated sign-in flow (discovery, IdP redirect,
  OIDC callback, SAML ACS).
* ``/v1/organizations/{id}/sso`` — authenticated CRUD for connections
  (``org.manage``).
"""

from __future__ import annotations

import time
import uuid
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.exceptions import HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select

from ..auth import service as auth_service
from ..auth.dependencies import DbSession, Principal, require_permission
from ..config import get_settings
from ..models import SsoConnection
from ..models.enums import SsoProtocol
from . import oidc, saml, service

public_router = APIRouter(prefix="/v1/auth/sso", tags=["auth"])
admin_router = APIRouter(prefix="/v1/organizations", tags=["sso"])

_STATE_TTL = 600
_SECRET_KEYS = ("client_secret", "sp_private_key")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _meta(request: Request) -> auth_service.RequestMeta:
    return auth_service.RequestMeta(
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )


def _api_base() -> str:
    return get_settings().oauth_redirect_base_url.rstrip("/")


def _callback_uri(cid: uuid.UUID) -> str:
    return f"{_api_base()}/v1/auth/sso/{cid}/callback"


def _sign_state(cid: uuid.UUID) -> str:
    s = get_settings()
    now = int(time.time())
    return jwt.encode(
        {"cid": str(cid), "typ": "sso", "iat": now, "exp": now + _STATE_TTL},
        s.secret_key,
        algorithm=s.jwt_algorithm,
    )


def _read_state(state: str, cid: uuid.UUID) -> None:
    s = get_settings()
    try:
        payload = jwt.decode(state, s.secret_key, algorithms=[s.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired SSO state") from exc
    if payload.get("typ") != "sso" or payload.get("cid") != str(cid):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO state does not match connection")


async def _load_enabled(db: DbSession, cid: uuid.UUID) -> SsoConnection:
    conn = await db.get(SsoConnection, cid)
    if conn is None or not conn.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO connection not found")
    return conn


async def _finish(
    request: Request, db: DbSession, conn: SsoConnection, profile
) -> RedirectResponse:
    user = await service.provision(
        db,
        conn=conn,
        subject=profile.subject,
        email=profile.email,
        name=getattr(profile, "name", None),
        raw=getattr(profile, "raw", None) or getattr(profile, "attributes", {}),
    )
    sess, refresh_plain = await auth_service.create_session(
        db,
        user=user,
        organization_id=conn.organization_id,
        meta=_meta(request),
        mfa_satisfied=True,
    )
    tokens = auth_service.issue_tokens(user=user, sess=sess, refresh_plain=refresh_plain)
    frag = (
        f"access_token={tokens.access_token}"
        f"&refresh_token={tokens.refresh_token}"
        f"&expires_in={tokens.expires_in}"
        f"&organization_id={conn.organization_id}"
    )
    web = get_settings().web_base_url.rstrip("/")
    return RedirectResponse(f"{web}/sso/callback#{frag}", status_code=status.HTTP_303_SEE_OTHER)


def _login_error(message: str) -> RedirectResponse:
    web = get_settings().web_base_url.rstrip("/")
    return RedirectResponse(
        f"{web}/login?sso_error={message}", status_code=status.HTTP_303_SEE_OTHER
    )


# --------------------------------------------------------------------------
# sign-in flow
# --------------------------------------------------------------------------


class DiscoverRequest(BaseModel):
    email: EmailStr


class DiscoverResponse(BaseModel):
    sso: bool
    enforced: bool = False
    connection_id: uuid.UUID | None = None
    name: str | None = None
    protocol: SsoProtocol | None = None
    login_url: str | None = None


@public_router.post("/discover", response_model=DiscoverResponse)
async def discover(body: DiscoverRequest, db: DbSession) -> DiscoverResponse:
    conn = await service.connection_for_email(db, str(body.email))
    if conn is None:
        return DiscoverResponse(sso=False)
    return DiscoverResponse(
        sso=True,
        enforced=conn.enforced,
        connection_id=conn.id,
        name=conn.name,
        protocol=conn.protocol,
        login_url=f"{_api_base()}/v1/auth/sso/{conn.id}/login",
    )


@public_router.get("/{cid}/login")
async def login(cid: uuid.UUID, db: DbSession) -> RedirectResponse:
    conn = await _load_enabled(db, cid)
    state = _sign_state(cid)
    try:
        if conn.protocol == SsoProtocol.oidc:
            url = oidc.authorization_url(conn, state=state, redirect_uri=_callback_uri(cid))
        else:
            url = saml.build_redirect(conn, base_url=_api_base(), relay_state=state)
    except (oidc.OidcError, saml.SamlError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@public_router.get("/{cid}/callback")
async def oidc_callback(
    cid: uuid.UUID,
    request: Request,
    db: DbSession,
    code: str | None = None,
    state: str | None = None,
) -> RedirectResponse:
    conn = await _load_enabled(db, cid)
    if conn.protocol != SsoProtocol.oidc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "connection is not OIDC")
    if not code or not state:
        return _login_error("missing_code")
    _read_state(state, cid)
    try:
        profile = await oidc.exchange(conn, code=code, redirect_uri=_callback_uri(cid))
    except oidc.OidcError as exc:
        return _login_error(str(exc)[:120])
    return await _finish(request, db, conn, profile)


@public_router.post("/{cid}/acs")
async def saml_acs(
    cid: uuid.UUID,
    request: Request,
    db: DbSession,
    SAMLResponse: Annotated[str, Form()],
    RelayState: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    conn = await _load_enabled(db, cid)
    if conn.protocol != SsoProtocol.saml:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "connection is not SAML")
    if RelayState:
        _read_state(RelayState, cid)
    try:
        profile = saml.parse_response(conn, SAMLResponse, base_url=_api_base())
    except saml.SamlError as exc:
        return _login_error(str(exc)[:120])
    return await _finish(request, db, conn, profile)


# --------------------------------------------------------------------------
# admin CRUD
# --------------------------------------------------------------------------

ManageDep = Annotated[Principal, Depends(require_permission("org.manage"))]


class ConnectionIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    protocol: SsoProtocol
    domains: list[str] = Field(default_factory=list)
    enabled: bool = True
    enforced: bool = False
    default_role: str = "developer"
    config: dict = Field(default_factory=dict)


class ConnectionPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    domains: list[str] | None = None
    enabled: bool | None = None
    enforced: bool | None = None
    default_role: str | None = None
    config: dict | None = None


class ConnectionOut(BaseModel):
    id: uuid.UUID
    name: str
    protocol: SsoProtocol
    domains: list[str]
    enabled: bool
    enforced: bool
    default_role: str
    config: dict
    acs_url: str | None = None
    metadata_url: str | None = None


def _redact(config: dict) -> dict:
    out = dict(config or {})
    for key in _SECRET_KEYS:
        if out.get(key):
            out[key] = "********"
    return out


def _out(conn: SsoConnection) -> ConnectionOut:
    acs = meta = None
    if conn.protocol == SsoProtocol.saml:
        acs = saml.acs_url(_api_base(), str(conn.id))
        meta = f"{_api_base()}/v1/organizations/{conn.organization_id}/sso/{conn.id}/metadata"
    return ConnectionOut(
        id=conn.id,
        name=conn.name,
        protocol=conn.protocol,
        domains=list(conn.domains or []),
        enabled=conn.enabled,
        enforced=conn.enforced,
        default_role=conn.default_role.value,
        config=_redact(conn.config),
        acs_url=acs,
        metadata_url=meta,
    )


def _scoped(principal: Principal, organization_id: uuid.UUID) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")


def _role(value: str):
    from ..models.enums import MembershipRole

    try:
        return MembershipRole(value)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role '{value}'"
        ) from exc


async def _normalize_oidc(config: dict) -> dict:
    """Fill authorization/token/jwks endpoints from the issuer's discovery doc."""
    cfg = dict(config)
    issuer = cfg.get("issuer")
    if issuer and not cfg.get("token_endpoint"):
        try:
            doc = await oidc.discover(issuer)
        except oidc.OidcError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"):
            if doc.get(key) and not cfg.get(key):
                cfg[key] = doc[key]
        cfg["issuer"] = doc["issuer"]
    return cfg


@admin_router.get("/{organization_id}/sso", response_model=list[ConnectionOut])
async def list_connections(
    organization_id: uuid.UUID, db: DbSession, principal: ManageDep
) -> list[ConnectionOut]:
    _scoped(principal, organization_id)
    rows = (
        await db.scalars(
            select(SsoConnection).where(SsoConnection.organization_id == organization_id)
        )
    ).all()
    return [_out(c) for c in rows]


@admin_router.post(
    "/{organization_id}/sso", response_model=ConnectionOut, status_code=status.HTTP_201_CREATED
)
async def create_connection(
    organization_id: uuid.UUID, body: ConnectionIn, db: DbSession, principal: ManageDep
) -> ConnectionOut:
    _scoped(principal, organization_id)
    dup = await db.scalar(
        select(SsoConnection.id).where(
            SsoConnection.organization_id == organization_id, SsoConnection.name == body.name
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "a connection with that name exists")
    config = body.config
    if body.protocol == SsoProtocol.oidc:
        config = await _normalize_oidc(config)
    conn = SsoConnection(
        organization_id=organization_id,
        name=body.name,
        protocol=body.protocol,
        domains=[d.strip().lower() for d in body.domains if d.strip()],
        enabled=body.enabled,
        enforced=body.enforced,
        default_role=_role(body.default_role),
        config=config,
    )
    db.add(conn)
    await db.flush()
    return _out(conn)


async def _load(db: DbSession, principal: Principal, organization_id: uuid.UUID, cid: uuid.UUID):
    _scoped(principal, organization_id)
    conn = await db.get(SsoConnection, cid)
    if conn is None or conn.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO connection not found")
    return conn


@admin_router.get("/{organization_id}/sso/{cid}", response_model=ConnectionOut)
async def get_connection(
    organization_id: uuid.UUID, cid: uuid.UUID, db: DbSession, principal: ManageDep
) -> ConnectionOut:
    return _out(await _load(db, principal, organization_id, cid))


@admin_router.patch("/{organization_id}/sso/{cid}", response_model=ConnectionOut)
async def update_connection(
    organization_id: uuid.UUID,
    cid: uuid.UUID,
    body: ConnectionPatch,
    db: DbSession,
    principal: ManageDep,
) -> ConnectionOut:
    conn = await _load(db, principal, organization_id, cid)
    if body.name is not None:
        conn.name = body.name
    if body.domains is not None:
        conn.domains = [d.strip().lower() for d in body.domains if d.strip()]
    if body.enabled is not None:
        conn.enabled = body.enabled
    if body.enforced is not None:
        conn.enforced = body.enforced
    if body.default_role is not None:
        conn.default_role = _role(body.default_role)
    if body.config is not None:
        merged = {**conn.config, **body.config}
        # a redacted secret coming back from the UI must not overwrite the real one
        for key in _SECRET_KEYS:
            if body.config.get(key) in {"********", ""}:
                merged[key] = conn.config.get(key)
        if conn.protocol == SsoProtocol.oidc:
            merged = await _normalize_oidc(merged)
        conn.config = merged
    await db.flush()
    return _out(conn)


@admin_router.delete("/{organization_id}/sso/{cid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(
    organization_id: uuid.UUID, cid: uuid.UUID, db: DbSession, principal: ManageDep
) -> Response:
    conn = await _load(db, principal, organization_id, cid)
    await db.delete(conn)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/{organization_id}/sso/{cid}/metadata")
async def sp_metadata(
    organization_id: uuid.UUID, cid: uuid.UUID, db: DbSession, principal: ManageDep
) -> Response:
    conn = await _load(db, principal, organization_id, cid)
    if conn.protocol != SsoProtocol.saml:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "connection is not SAML")
    return Response(content=saml.sp_metadata(conn, _api_base()), media_type="application/xml")
