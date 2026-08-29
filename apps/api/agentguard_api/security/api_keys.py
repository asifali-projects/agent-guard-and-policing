"""API key generation and verification — PRD §52.

Format:  ag_<env>_<publicid>_<secret>

- ``env`` — one of dev / stg / live, so a leaked key's blast radius is obvious.
- ``publicid`` — 8 chars, stored in clear for lookup + display.
- ``secret`` — 32 url-safe chars, only its Argon2 hash is stored.

The full key is shown to the user exactly once, at creation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from ..models.enums import Environment

_hasher = PasswordHasher()

_ENV_SHORT = {
    Environment.development: "dev",
    Environment.staging: "stg",
    Environment.production: "live",
}
_SHORT_ENV = {v: k for k, v in _ENV_SHORT.items()}


@dataclass(frozen=True)
class ApiKeyParts:
    environment: Environment
    public_id: str
    secret: str

    @property
    def prefix(self) -> str:
        """The non-secret portion, safe to store and display."""
        return f"ag_{_ENV_SHORT[self.environment]}_{self.public_id}"


def generate_api_key(environment: Environment) -> tuple[str, ApiKeyParts]:
    """Return ``(full_key, parts)``. Persist ``parts.prefix`` + hash of ``parts.secret``."""
    public_id = secrets.token_hex(4)  # 8 chars
    secret = secrets.token_urlsafe(24)
    parts = ApiKeyParts(environment=environment, public_id=public_id, secret=secret)
    return f"{parts.prefix}_{secret}", parts


def parse_api_key(full_key: str) -> ApiKeyParts | None:
    bits = full_key.split("_", 3)
    if len(bits) != 4 or bits[0] != "ag" or bits[1] not in _SHORT_ENV:
        return None
    _, env_short, public_id, secret = bits
    if not public_id or not secret:
        return None
    return ApiKeyParts(environment=_SHORT_ENV[env_short], public_id=public_id, secret=secret)


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(secret: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, secret)
    except (VerifyMismatchError, InvalidHashError):
        return False
