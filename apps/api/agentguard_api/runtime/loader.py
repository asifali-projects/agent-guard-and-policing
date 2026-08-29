"""Load the policy set that applies to one attempted tool call.

Enabled policies bound anywhere in an organization are cached in Redis as a
single blob per org, versioned by `pver:{org}` (bumped on any policy/binding
write). Per request we filter that blob down to the bindings that apply to this
environment / agent / tool / action and compile them for the engine.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

from agentguard_policy import CompiledPolicy, PolicySpec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import get_client
from ..models import Policy, PolicyBinding, Tool
from ..models.enums import PolicyScopeType

_CACHE_TTL = 30
_SPECIFICITY = {
    PolicyScopeType.organization: 0,
    PolicyScopeType.environment: 1,
    PolicyScopeType.agent: 2,
    PolicyScopeType.tool: 3,
    PolicyScopeType.action: 4,
}


@dataclass(frozen=True)
class _Binding:
    policy_key: str
    priority: int
    scope_type: str
    environment: str | None
    agent_id: str | None
    tool_id: str | None
    action: str | None
    spec: dict


def _pver_key(org_id: uuid.UUID) -> str:
    return f"pver:{org_id}"


def _blob_key(org_id: uuid.UUID, version: str) -> str:
    return f"pset:{org_id}:v{version}"


async def bump_version(org_id: uuid.UUID) -> None:
    await get_client().incr(_pver_key(org_id))


async def _load_bindings(session: AsyncSession, org_id: uuid.UUID) -> list[_Binding]:
    rows = (
        await session.execute(
            select(PolicyBinding, Policy)
            .join(Policy, Policy.id == PolicyBinding.policy_id)
            .where(PolicyBinding.organization_id == org_id, Policy.enabled.is_(True))
        )
    ).all()
    out: list[_Binding] = []
    for binding, policy in rows:
        out.append(
            _Binding(
                policy_key=policy.key,
                priority=policy.priority,
                scope_type=binding.scope_type.value,
                environment=binding.environment.value if binding.environment else None,
                agent_id=str(binding.agent_id) if binding.agent_id else None,
                tool_id=str(binding.tool_id) if binding.tool_id else None,
                action=binding.action,
                spec=policy.spec,
            )
        )
    return out


async def _cached_bindings(session: AsyncSession, org_id: uuid.UUID) -> list[_Binding]:
    redis = get_client()
    version = await redis.get(_pver_key(org_id)) or "0"
    key = _blob_key(org_id, version)
    raw = await redis.get(key)
    if raw is not None:
        return [_Binding(**b) for b in json.loads(raw)]

    bindings = await _load_bindings(session, org_id)
    await redis.set(key, json.dumps([b.__dict__ for b in bindings]), ex=_CACHE_TTL)
    return bindings


def _applies(
    b: _Binding, *, environment: str, agent_id: str, tool_id: str | None, action: str
) -> bool:
    st = b.scope_type
    if st == "organization":
        return True
    if st == "environment":
        return b.environment == environment
    if st == "agent":
        return b.agent_id == agent_id
    if st == "tool":
        return tool_id is not None and b.tool_id == tool_id
    if st == "action":
        if b.agent_id and b.agent_id != agent_id:
            return False
        if b.tool_id and b.tool_id != tool_id:
            return False
        return b.action in (None, action)
    return False


async def load_policy_set(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    environment: str,
    agent_id: uuid.UUID,
    tool_name: str,
    action: str,
) -> tuple[list[CompiledPolicy], bool]:
    """Return ``(compiled_policies, cache_hit)``."""
    redis = get_client()
    version = await redis.get(_pver_key(organization_id)) or "0"
    cache_hit = await redis.exists(_blob_key(organization_id, version)) == 1

    bindings = await _cached_bindings(session, organization_id)

    tool_id = await session.scalar(
        select(Tool.id).where(Tool.organization_id == organization_id, Tool.name == tool_name)
    )
    tool_id_str = str(tool_id) if tool_id else None

    compiled: dict[str, CompiledPolicy] = {}
    for b in bindings:
        if not _applies(
            b,
            environment=environment,
            agent_id=str(agent_id),
            tool_id=tool_id_str,
            action=action,
        ):
            continue
        spec = PolicySpec.model_validate(b.spec)
        specificity = _SPECIFICITY.get(PolicyScopeType(b.scope_type), 0)
        existing = compiled.get(b.policy_key)
        if existing is None or specificity > existing.specificity:
            compiled[b.policy_key] = CompiledPolicy(
                key=b.policy_key, spec=spec, priority=b.priority, specificity=specificity
            )
    return list(compiled.values()), cache_hit
