"""Primitive security helpers: password hashing, JWTs, API keys, TOTP.

Nothing here touches the database or FastAPI — pure functions only.
"""

from .api_keys import ApiKeyParts, generate_api_key, hash_secret, parse_api_key, verify_secret
from .passwords import hash_password, needs_rehash, verify_password
from .tokens import (
    TokenError,
    decode_access_token,
    hash_token,
    new_access_token,
    new_opaque_token,
)
from .totp import new_secret as new_totp_secret
from .totp import totp_provisioning_uri, verify_totp

__all__ = [
    "ApiKeyParts",
    "TokenError",
    "decode_access_token",
    "generate_api_key",
    "hash_password",
    "hash_secret",
    "hash_token",
    "needs_rehash",
    "new_access_token",
    "new_opaque_token",
    "new_totp_secret",
    "parse_api_key",
    "totp_provisioning_uri",
    "verify_password",
    "verify_secret",
    "verify_totp",
]
