"""OAuth 2.0 / OIDC sign-in for Google and Microsoft (PRD §9).

A provider is available only when its client id + secret are configured. The
state parameter is a signed short-lived JWT so no server-side state is needed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt

from ..config import get_settings


class OAuthError(Exception):
    pass


@dataclass(frozen=True)
class OAuthProfile:
    provider: str
    subject: str
    email: str | None
    full_name: str | None
    raw: dict


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str
    client_id: str
    client_secret: str


def _providers() -> dict[str, ProviderConfig]:
    s = get_settings()
    out: dict[str, ProviderConfig] = {}
    if s.google_client_id and s.google_client_secret:
        out["google"] = ProviderConfig(
            name="google",
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
            scope="openid email profile",
            client_id=s.google_client_id,
            client_secret=s.google_client_secret,
        )
    if s.microsoft_client_id and s.microsoft_client_secret:
        tenant = s.microsoft_tenant
        out["microsoft"] = ProviderConfig(
            name="microsoft",
            authorize_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            token_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/oidc/userinfo",
            scope="openid email profile",
            client_id=s.microsoft_client_id,
            client_secret=s.microsoft_client_secret,
        )
    return out


def available_providers() -> list[str]:
    return sorted(_providers())


def get_provider(name: str) -> ProviderConfig:
    try:
        return _providers()[name]
    except KeyError as exc:
        raise OAuthError(f"provider '{name}' is not configured") from exc


def _redirect_uri(provider: str) -> str:
    base = get_settings().oauth_redirect_base_url.rstrip("/")
    return f"{base}/v1/auth/oauth/{provider}/callback"


def build_state(provider: str, organization_id: str | None) -> str:
    s = get_settings()
    now = int(time.time())
    return jwt.encode(
        {"provider": provider, "org": organization_id, "iat": now, "exp": now + 600},
        s.secret_key,
        algorithm=s.jwt_algorithm,
    )


def read_state(state: str) -> dict:
    s = get_settings()
    try:
        return jwt.decode(state, s.secret_key, algorithms=[s.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise OAuthError("invalid or expired state") from exc


def authorization_url(provider: str, organization_id: str | None) -> str:
    cfg = get_provider(provider)
    params = {
        "client_id": cfg.client_id,
        "response_type": "code",
        "redirect_uri": _redirect_uri(provider),
        "scope": cfg.scope,
        "state": build_state(provider, organization_id),
        "access_type": "offline",
        "prompt": "select_account",
    }
    return f"{cfg.authorize_url}?{urlencode(params)}"


async def exchange_code(provider: str, code: str) -> OAuthProfile:
    cfg = get_provider(provider)
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            cfg.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _redirect_uri(provider),
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            raise OAuthError(f"token exchange failed: {token_resp.text}")
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise OAuthError("no access_token in provider response")

        info_resp = await client.get(
            cfg.userinfo_url, headers={"Authorization": f"Bearer {access_token}"}
        )
        if info_resp.status_code != 200:
            raise OAuthError(f"userinfo failed: {info_resp.text}")
        info = info_resp.json()

    subject = str(info.get("sub") or info.get("oid") or info.get("id") or "")
    if not subject:
        raise OAuthError("provider profile has no stable subject")
    return OAuthProfile(
        provider=provider,
        subject=subject,
        email=(info.get("email") or "").lower() or None,
        full_name=info.get("name"),
        raw=info,
    )
