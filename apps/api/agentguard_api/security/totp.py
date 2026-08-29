"""TOTP (RFC 6238) helpers for MFA — PRD §9, §51.

The shared secret is stored on the user row. In production it must be encrypted
with a customer- or platform-managed key (PRD §75); that wrapping is added with
the secrets-management work and is out of scope for this step.
"""

from __future__ import annotations

import pyotp

from ..config import get_settings


def new_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account_name: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name=get_settings().mfa_issuer
    )


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=valid_window)
