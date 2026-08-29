"""Enterprise SSO — generic OIDC + SAML 2.0 (PRD §9, §51)."""

from .service import connection_for_email, enforced_for_email, provision

__all__ = ["connection_for_email", "enforced_for_email", "provision"]
