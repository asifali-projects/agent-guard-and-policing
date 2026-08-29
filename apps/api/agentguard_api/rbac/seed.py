"""Idempotent seed of the RBAC catalog + built-in plans.

    python -m agentguard_api.rbac.seed

Safe to run repeatedly (upserts by natural key). Runs in the compose `migrate`
one-shot and in CI after `alembic upgrade head`.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models import Permission, Plan, Role
from ..models.enums import MembershipRole, PlanCode
from .catalog import PERMISSIONS, SYSTEM_ROLE_GRANTS

# PRD §64–65 — public plan tiers with metered limits (advisory, not hard caps).
_PLANS: list[dict] = [
    {
        "code": PlanCode.community,
        "name": "Community",
        "monthly_price_cents": 0,
        "is_public": True,
        "limits": {"agents": 3, "users": 3, "runtime_actions": 50_000, "redteam_tests": 500},
    },
    {
        "code": PlanCode.developer,
        "name": "Developer",
        "monthly_price_cents": 4900,
        "is_public": True,
        "limits": {"agents": 10, "users": 5, "runtime_actions": 500_000, "redteam_tests": 5_000},
    },
    {
        "code": PlanCode.team,
        "name": "Team",
        "monthly_price_cents": 29900,
        "is_public": True,
        "limits": {
            "agents": 50,
            "users": 25,
            "runtime_actions": 5_000_000,
            "redteam_tests": 50_000,
        },
    },
    {
        "code": PlanCode.business,
        "name": "Business",
        "monthly_price_cents": 99900,
        "is_public": True,
        "limits": {
            "agents": 250,
            "users": 100,
            "runtime_actions": 50_000_000,
            "redteam_tests": 500_000,
        },
    },
    {
        "code": PlanCode.enterprise,
        "name": "Enterprise",
        "monthly_price_cents": 0,
        "is_public": False,
        "limits": {},
    },
]


async def _seed_permissions(session: AsyncSession) -> dict[str, Permission]:
    existing = {p.code: p for p in (await session.scalars(select(Permission))).all()}
    for code, (category, description) in PERMISSIONS.items():
        row = existing.get(code)
        if row is None:
            row = Permission(code=code, category=category, description=description)
            session.add(row)
            existing[code] = row
        else:
            row.category, row.description = category, description
    await session.flush()
    return existing


async def _seed_roles(session: AsyncSession, perms: dict[str, Permission]) -> None:
    existing = {
        r.name: r
        for r in (
            await session.scalars(
                select(Role).where(Role.is_system.is_(True)).options(selectinload(Role.permissions))
            )
        ).all()
    }
    for role in MembershipRole:
        granted = SYSTEM_ROLE_GRANTS.get(role, frozenset())
        row = existing.get(role.value)
        if row is None:
            row = Role(
                organization_id=None,
                name=role.value,
                description=f"Built-in {role.value.replace('_', ' ')} role",
                is_system=True,
            )
            session.add(row)
        row.permissions = [perms[c] for c in sorted(granted)]
    await session.flush()


async def _seed_plans(session: AsyncSession) -> None:
    existing = {p.code: p for p in (await session.scalars(select(Plan))).all()}
    for spec in _PLANS:
        row = existing.get(spec["code"])
        if row is None:
            session.add(Plan(**spec))
        else:
            row.name = spec["name"]
            row.monthly_price_cents = spec["monthly_price_cents"]
            row.is_public = spec["is_public"]
            row.limits = spec["limits"]
    await session.flush()


async def seed(session: AsyncSession) -> None:
    perms = await _seed_permissions(session)
    await _seed_roles(session, perms)
    await _seed_plans(session)
    await session.commit()


async def _main() -> None:
    from ..db import get_engine

    engine = get_engine()
    async with AsyncSession(engine) as session:
        await seed(session)
    await engine.dispose()
    print(
        f"seeded {len(PERMISSIONS)} permissions, {len(MembershipRole)} roles, {len(_PLANS)} plans"
    )


if __name__ == "__main__":
    asyncio.run(_main())
