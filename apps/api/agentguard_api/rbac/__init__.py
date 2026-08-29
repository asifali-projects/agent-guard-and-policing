"""Role-based access control — PRD §50.

`catalog.py` is the source of truth for the permission list and the built-in
role grants. `seed.py` mirrors it into the `permissions` / `roles` /
`role_permissions` tables so custom roles can be built on the same vocabulary.
"""

from .catalog import PERMISSIONS, SYSTEM_ROLE_GRANTS, permissions_for_role

__all__ = ["PERMISSIONS", "SYSTEM_ROLE_GRANTS", "permissions_for_role"]
