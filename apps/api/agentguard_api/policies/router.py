"""Policy endpoints — /v1/policies (PRD §23, §36 `agentguard policy validate`)."""

from __future__ import annotations

import uuid
from typing import Annotated

from agentguard_policy import EvaluationInput, PolicySpec, evaluate
from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import ValidationError
from sqlalchemy import func, select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import Agent, Policy, PolicyBinding, PolicyVersion
from ..models.enums import ActorType
from ..runtime.loader import load_policy_set
from . import service
from .schemas import (
    BindingIn,
    BindingOut,
    PolicyIn,
    PolicyOut,
    PolicyUpdate,
    SimulateIn,
    SimulateOut,
    ValidateIn,
    ValidateOut,
)

router = APIRouter(prefix="/v1/policies", tags=["policies"])

ReadDep = Annotated[Principal, Depends(require_permission("policy.read"))]
ManageDep = Annotated[Principal, Depends(require_permission("policy.manage"))]


async def _version(db, policy_id: uuid.UUID) -> int:
    return (
        await db.scalar(
            select(func.max(PolicyVersion.version)).where(PolicyVersion.policy_id == policy_id)
        )
    ) or 1


def _out(policy: Policy, version: int) -> PolicyOut:
    return PolicyOut(
        id=policy.id,
        key=policy.key,
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        priority=policy.priority,
        spec=policy.spec,
        version=version,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


async def _load(db, principal: Principal, policy_id: uuid.UUID) -> Policy:
    policy = await db.get(Policy, policy_id)
    if policy is None or policy.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
    return policy


@router.post("/validate", response_model=ValidateOut)
async def validate_policy(body: ValidateIn, principal: ReadDep) -> ValidateOut:
    try:
        spec = PolicySpec.model_validate(body.spec)
    except ValidationError as exc:
        return ValidateOut(valid=False, errors=[e["msg"] for e in exc.errors()])
    return ValidateOut(valid=True, rule_count=len(spec.rules))


@router.get("", response_model=list[PolicyOut])
async def list_policies(db: DbSession, principal: ReadDep) -> list[PolicyOut]:
    rows = (
        await db.scalars(
            select(Policy)
            .where(Policy.organization_id == principal.organization_id)
            .order_by(Policy.key)
        )
    ).all()
    return [_out(p, await _version(db, p.id)) for p in rows]


@router.post("", response_model=PolicyOut, status_code=status.HTTP_201_CREATED)
async def create_policy(body: PolicyIn, db: DbSession, principal: ManageDep) -> PolicyOut:
    try:
        policy = await service.create_policy(
            db,
            organization_id=principal.organization_id,
            created_by_id=principal.user_id,
            key=body.key,
            name=body.name,
            description=body.description,
            enabled=body.enabled,
            priority=body.priority,
            spec=body.spec,
        )
    except service.PolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="policy.create",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        policy_key=policy.key,
    )
    return _out(policy, 1)


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(policy_id: uuid.UUID, db: DbSession, principal: ReadDep) -> PolicyOut:
    policy = await _load(db, principal, policy_id)
    return _out(policy, await _version(db, policy.id))


@router.patch("/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: uuid.UUID, body: PolicyUpdate, db: DbSession, principal: ManageDep
) -> PolicyOut:
    policy = await _load(db, principal, policy_id)
    try:
        await service.update_policy(
            db,
            policy,
            updated_by_id=principal.user_id,
            name=body.name,
            description=body.description,
            enabled=body.enabled,
            priority=body.priority,
            spec=body.spec,
        )
    except service.PolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="policy.update",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        policy_key=policy.key,
    )
    return _out(policy, await _version(db, policy.id))


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: uuid.UUID, db: DbSession, principal: ManageDep) -> Response:
    policy = await _load(db, principal, policy_id)
    key = policy.key
    await service.delete_policy(db, policy)
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="policy.delete",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        policy_key=key,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- bindings -------------------------------------------------------------


@router.get("/{policy_id}/bindings", response_model=list[BindingOut])
async def list_bindings(
    policy_id: uuid.UUID, db: DbSession, principal: ReadDep
) -> list[BindingOut]:
    await _load(db, principal, policy_id)
    rows = (
        await db.scalars(select(PolicyBinding).where(PolicyBinding.policy_id == policy_id))
    ).all()
    return [
        BindingOut(
            id=b.id,
            policy_id=b.policy_id,
            scope_type=b.scope_type,
            environment=b.environment,
            agent_id=b.agent_id,
            tool_id=b.tool_id,
            action=b.action,
        )
        for b in rows
    ]


@router.post(
    "/{policy_id}/bindings", response_model=BindingOut, status_code=status.HTTP_201_CREATED
)
async def create_binding(
    policy_id: uuid.UUID, body: BindingIn, db: DbSession, principal: ManageDep
) -> BindingOut:
    policy = await _load(db, principal, policy_id)
    if body.agent_id is not None:
        agent = await db.get(Agent, body.agent_id)
        if agent is None or agent.organization_id != principal.organization_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent not in organization")
    binding = await service.add_binding(
        db,
        policy,
        PolicyBinding(
            scope_type=body.scope_type,
            environment=body.environment,
            agent_id=body.agent_id,
            tool_id=body.tool_id,
            action=body.action,
        ),
    )
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="policy.bind",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        policy_key=policy.key,
        metadata={"scope": body.scope_type.value},
    )
    return BindingOut(
        id=binding.id,
        policy_id=binding.policy_id,
        scope_type=binding.scope_type,
        environment=binding.environment,
        agent_id=binding.agent_id,
        tool_id=binding.tool_id,
        action=binding.action,
    )


@router.delete("/{policy_id}/bindings/{binding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_binding(
    policy_id: uuid.UUID, binding_id: uuid.UUID, db: DbSession, principal: ManageDep
) -> Response:
    await _load(db, principal, policy_id)
    binding = await db.get(PolicyBinding, binding_id)
    if binding is None or binding.policy_id != policy_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "binding not found")
    await service.remove_binding(db, binding)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- simulate (dry run) --------------------------------------------------


@router.post("/simulate", response_model=SimulateOut)
async def simulate(body: SimulateIn, db: DbSession, principal: ReadDep) -> SimulateOut:
    agent = await db.get(Agent, body.agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    policies, _ = await load_policy_set(
        db,
        organization_id=principal.organization_id,
        environment=agent.environment.value,
        agent_id=body.agent_id,
        tool_name=body.tool,
        action=body.action,
    )
    result = evaluate(
        EvaluationInput(
            tool=body.tool,
            action=body.action,
            environment=agent.environment.value,
            agent_id=str(body.agent_id),
            parameters=body.parameters,
            context=body.context,
            data_classification=body.data_classification,
        ),
        policies,
    )
    return SimulateOut(
        decision=result.decision.value.upper(),
        policy_keys=result.matched_policy_keys,
        reasons=result.reasons,
        redactions=result.redactions,
        default_applied=result.default_applied,
    )
