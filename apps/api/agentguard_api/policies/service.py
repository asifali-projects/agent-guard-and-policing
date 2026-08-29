"""Policy CRUD + binding management, with cache invalidation."""

from __future__ import annotations

import uuid

from agentguard_policy import PolicySpec
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Policy, PolicyBinding, PolicyVersion
from ..runtime.loader import bump_version


class PolicyError(Exception):
    """Invalid policy spec or duplicate key (maps to 4xx)."""


def validate_spec(spec: dict) -> PolicySpec:
    try:
        return PolicySpec.model_validate(spec)
    except ValidationError as exc:
        raise PolicyError("; ".join(e["msg"] for e in exc.errors())) from exc


async def _next_version(session: AsyncSession, policy_id: uuid.UUID) -> int:
    current = await session.scalar(
        select(func.max(PolicyVersion.version)).where(PolicyVersion.policy_id == policy_id)
    )
    return (current or 0) + 1


async def create_policy(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    created_by_id: uuid.UUID | None,
    key: str,
    name: str,
    description: str | None,
    enabled: bool,
    priority: int,
    spec: dict,
) -> Policy:
    validate_spec(spec)
    dup = await session.scalar(
        select(Policy.id).where(Policy.organization_id == organization_id, Policy.key == key)
    )
    if dup:
        raise PolicyError(f"policy key '{key}' already exists")

    policy = Policy(
        organization_id=organization_id,
        key=key,
        name=name,
        description=description,
        enabled=enabled,
        priority=priority,
        spec=spec,
        created_by_id=created_by_id,
    )
    session.add(policy)
    await session.flush()
    session.add(
        PolicyVersion(policy_id=policy.id, version=1, spec=spec, created_by_id=created_by_id)
    )
    await session.flush()
    await bump_version(organization_id)
    return policy


async def update_policy(
    session: AsyncSession,
    policy: Policy,
    *,
    updated_by_id: uuid.UUID | None,
    name: str | None,
    description: str | None,
    enabled: bool | None,
    priority: int | None,
    spec: dict | None,
) -> Policy:
    if spec is not None:
        validate_spec(spec)
        policy.spec = spec
        session.add(
            PolicyVersion(
                policy_id=policy.id,
                version=await _next_version(session, policy.id),
                spec=spec,
                created_by_id=updated_by_id,
            )
        )
    if name is not None:
        policy.name = name
    if description is not None:
        policy.description = description
    if enabled is not None:
        policy.enabled = enabled
    if priority is not None:
        policy.priority = priority
    await session.flush()
    await bump_version(policy.organization_id)
    return policy


async def delete_policy(session: AsyncSession, policy: Policy) -> None:
    org_id = policy.organization_id
    await session.delete(policy)
    await session.flush()
    await bump_version(org_id)


async def add_binding(
    session: AsyncSession, policy: Policy, binding: PolicyBinding
) -> PolicyBinding:
    binding.policy_id = policy.id
    binding.organization_id = policy.organization_id
    session.add(binding)
    await session.flush()
    await bump_version(policy.organization_id)
    return binding


async def remove_binding(session: AsyncSession, binding: PolicyBinding) -> None:
    org_id = binding.organization_id
    await session.delete(binding)
    await session.flush()
    await bump_version(org_id)
