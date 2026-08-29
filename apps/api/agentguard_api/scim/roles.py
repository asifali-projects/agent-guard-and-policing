"""Map SCIM group display names to AgentGuard roles (PRD §50–51).

A group is "role-mapped" when its display name matches a built-in role, in any
of these spellings (case-insensitive)::

    security_admin   |   security-admin   |   Security Admin
    agentguard:security_admin   |   AgentGuard Security Admin

When a user belongs to several mapped groups the highest-privilege role wins.
SCIM never provisions an ``owner``; a group that maps to it is treated as
``admin``.
"""

from __future__ import annotations

import re

from ..models.enums import MembershipRole

# most privileged first
_PRIORITY: list[MembershipRole] = [
    MembershipRole.admin,
    MembershipRole.security_admin,
    MembershipRole.security_analyst,
    MembershipRole.developer,
    MembershipRole.billing_admin,
    MembershipRole.auditor,
]
_RANK = {role: i for i, role in enumerate(_PRIORITY)}


def role_from_display_name(display_name: str) -> MembershipRole | None:
    slug = re.sub(r"[^a-z0-9]+", "_", display_name.strip().lower()).strip("_")
    slug = slug.removeprefix("agentguard_")
    if slug == "owner":
        return MembershipRole.admin
    try:
        return MembershipRole(slug)
    except ValueError:
        return None


def most_privileged(roles: list[MembershipRole]) -> MembershipRole | None:
    ranked = [r for r in roles if r in _RANK]
    if not ranked:
        return None
    return min(ranked, key=lambda r: _RANK[r])
