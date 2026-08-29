"""Generic OIDC — discovery, authorization URL, code exchange + id_token check.

Works with any compliant provider (Okta, Microsoft Entra ID, Auth0, Google
Workspace, Ping, Keycloak, …).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from ..models import SsoConnection


class OidcError(Exception):
    pass


@dataclass(frozen=True)
class OidcProfile:
    subject: str
    email: str | None
    name: str | None
    raw: dict


async def discover(issuer: str) -> dict:
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url)
    if resp.status_code != 200:
        raise OidcError(f"discovery failed for {issuer}: {resp.status_code}")
    doc = resp.json()
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if key not in doc:
            raise OidcError(f"discovery document missing '{key}'")
    return doc


def _cfg(conn: SsoConnection) -> dict:
    return conn.config or {}


def authorization_url(conn: SsoConnection, *, state: str, redirect_uri: str) -> str:
    cfg = _cfg(conn)
    endpoint = cfg.get("authorization_endpoint")
    if not endpoint or not cfg.get("client_id"):
        raise OidcError("connection is missing authorization_endpoint / client_id")
    params = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": cfg.get("scopes", "openid email profile"),
        "state": state,
    }
    return f"{endpoint}?{urlencode(params)}"


def _verify_id_token(id_token: str, jwks: dict, *, audience: str, issuer: str) -> dict:
    header = jwt.get_unverified_header(id_token)
    kid, alg = header.get("kid"), header.get("alg", "RS256")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if jwk is None and len(jwks.get("keys", [])) == 1:
        jwk = jwks["keys"][0]
    if jwk is None:
        raise OidcError("no matching JWKS key for id_token")
    builder = ECAlgorithm if alg.startswith("ES") else RSAAlgorithm
    key = builder.from_jwk(json.dumps(jwk))
    try:
        return jwt.decode(
            id_token,
            key,
            algorithms=[alg],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"id_token verification failed: {exc}") from exc


async def exchange(conn: SsoConnection, *, code: str, redirect_uri: str) -> OidcProfile:
    cfg = _cfg(conn)
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            cfg["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": cfg["client_id"],
                "client_secret": cfg.get("client_secret", ""),
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            raise OidcError(f"token exchange failed: {token_resp.text}")
        tokens = token_resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise OidcError("no id_token in token response")

        jwks_resp = await client.get(cfg["jwks_uri"])
        jwks = jwks_resp.json()

    claims = _verify_id_token(id_token, jwks, audience=cfg["client_id"], issuer=cfg["issuer"])
    return OidcProfile(
        subject=str(claims["sub"]),
        email=(claims.get("email") or "").lower() or None,
        name=claims.get("name") or claims.get("preferred_username"),
        raw=claims,
    )
