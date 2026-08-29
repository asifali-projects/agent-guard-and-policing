"""JWT access tokens + opaque refresh tokens.

Access tokens are short-lived and stateless. Refresh tokens are opaque random
strings whose SHA-256 is stored in the `sessions` table so they can be rotated
and revoked (PRD §51).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

import jwt

from ..config import get_settings


class TokenError(Exception):
    """Raised when an access token is missing, malformed, or expired."""


def new_access_token(
    *,
    subject: str,
    organization_id: str | None,
    session_id: str,
    extra: dict[str, Any] | None = None,
) -> str:
    settings = get_settings()
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "sid": session_id,
        "org": organization_id,
        "iat": now,
        "nbf": now,
        "exp": now + settings.access_token_ttl_seconds,
        "iss": "agentguard",
        "typ": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="agentguard",
            options={"require": ["exp", "sub", "sid"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if payload.get("typ") != "access":
        raise TokenError("not an access token")
    return payload


def new_opaque_token(nbytes: int = 32) -> tuple[str, str]:
    """Return ``(plaintext, sha256_hex)``. Only the hash is persisted."""
    plaintext = secrets.token_urlsafe(nbytes)
    return plaintext, hash_token(plaintext)


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
