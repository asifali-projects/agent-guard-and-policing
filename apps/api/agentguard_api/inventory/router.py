"""Agent + tool inventory endpoints — /v1/agents, /v1/tools."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import Agent, AgentIdentity, Tool
from ..models.enums import (
    ActorType,
    AgentKind,
    AgentStatus,
    Environment,
    FailMode,
    Framework,
    PermissionScope,
    RiskSeverity,
    TrustLevel,
)

agents_router = APIRouter(prefix="/v1/agents", tags=["agents"])
tools_router = APIRouter(prefix="/v1/tools", tags=["tools"])

AgentRead = Annotated[Principal, Depends(require_permission("agent.read"))]
AgentManage = Annotated[Principal, Depends(require_permission("agent.manage"))]
ToolRead = Annotated[Principal, Depends(require_permission("tool.read"))]
ToolManage = Annotated[Principal, Depends(require_permission("tool.manage"))]


# --- agents ---------------------------------------------------------------


class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    kind: AgentKind = AgentKind.ai_agent
    framework: Framework = Framework.custom
    model: str | None = None
    environment: Environment = Environment.development
    owner_team: str | None = None
    description: str | None = None
    fail_mode: FailMode = FailMode.fail_closed
    tags: list[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.standard


class AgentPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    model: str | None = None
    owner_team: str | None = None
    description: str | None = None
    status: AgentStatus | None = None
    fail_mode: FailMode | None = None
    tags: list[str] | None = None


class AgentOut(BaseModel):
    id: uuid.UUID
    name: str
    kind: AgentKind
    framework: Framework
    model: str | None
    environment: Environment
    owner_team: str | None
    description: str | None
    status: AgentStatus
    risk_score: int | None
    fail_mode: FailMode
    tags: list[str]
    identity: str | None
    created_at: datetime
    updated_at: datetime


def _agent_out(a: Agent, identity: str | None) -> AgentOut:
    return AgentOut(
        id=a.id,
        name=a.name,
        kind=a.kind,
        framework=a.framework,
        model=a.model,
        environment=a.environment,
        owner_team=a.owner_team,
        description=a.description,
        status=a.status,
        risk_score=a.risk_score,
        fail_mode=a.fail_mode,
        tags=list(a.tags or []),
        identity=identity,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


async def _load_agent(db, principal: Principal, agent_id: uuid.UUID) -> Agent:
    agent = await db.get(Agent, agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    return agent


@agents_router.get("", response_model=list[AgentOut])
async def list_agents(db: DbSession, principal: AgentRead) -> list[AgentOut]:
    rows = (
        await db.scalars(
            select(Agent)
            .where(Agent.organization_id == principal.organization_id)
            .order_by(Agent.name)
        )
    ).all()
    out = []
    for a in rows:
        ident = await db.scalar(
            select(AgentIdentity.identity).where(AgentIdentity.agent_id == a.id)
        )
        out.append(_agent_out(a, ident))
    return out


@agents_router.post("", response_model=AgentOut, status_code=status.HTTP_201_CREATED)
async def create_agent(body: AgentIn, db: DbSession, principal: AgentManage) -> AgentOut:
    dup = await db.scalar(
        select(Agent.id).where(
            Agent.organization_id == principal.organization_id,
            Agent.name == body.name,
            Agent.environment == body.environment,
        )
    )
    if dup:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "agent with this name already exists in this environment"
        )
    agent = Agent(
        organization_id=principal.organization_id,
        name=body.name,
        kind=body.kind,
        framework=body.framework,
        model=body.model,
        environment=body.environment,
        owner_team=body.owner_team,
        description=body.description,
        fail_mode=body.fail_mode,
        tags=body.tags,
    )
    db.add(agent)
    await db.flush()

    slug = agent.name.lower().replace(" ", "-")
    identity = f"agent:{slug}-{agent.environment.value}-{agent.id.hex[:6]}"
    db.add(
        AgentIdentity(
            agent_id=agent.id,
            identity=identity,
            trust_level=body.trust_level,
            owner=body.owner_team,
            environment=body.environment,
        )
    )
    await db.flush()
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="agent.register",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        agent_id=agent.id,
        metadata={"name": agent.name, "environment": agent.environment.value},
    )
    return _agent_out(agent, identity)


@agents_router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(agent_id: uuid.UUID, db: DbSession, principal: AgentRead) -> AgentOut:
    agent = await _load_agent(db, principal, agent_id)
    ident = await db.scalar(
        select(AgentIdentity.identity).where(AgentIdentity.agent_id == agent.id)
    )
    return _agent_out(agent, ident)


@agents_router.patch("/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: uuid.UUID, body: AgentPatch, db: DbSession, principal: AgentManage
) -> AgentOut:
    agent = await _load_agent(db, principal, agent_id)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(agent, field, value)
    await db.flush()
    ident = await db.scalar(
        select(AgentIdentity.identity).where(AgentIdentity.agent_id == agent.id)
    )
    return _agent_out(agent, ident)


@agents_router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(agent_id: uuid.UUID, db: DbSession, principal: AgentManage) -> Response:
    agent = await _load_agent(db, principal, agent_id)
    await db.delete(agent)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- tools ---------------------------------------------------------------


class ToolIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    display_name: str | None = None
    description: str | None = None
    owner_team: str | None = None
    source: str | None = None
    risk: RiskSeverity = RiskSeverity.low
    permissions: list[PermissionScope] = Field(default_factory=list)
    destination: str | None = None


class ToolPatch(BaseModel):
    display_name: str | None = None
    description: str | None = None
    owner_team: str | None = None
    risk: RiskSeverity | None = None
    permissions: list[PermissionScope] | None = None
    destination: str | None = None


class ToolOut(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str | None
    description: str | None
    owner_team: str | None
    source: str | None
    risk: RiskSeverity
    permissions: list[str]
    destination: str | None
    created_at: datetime


def _tool_out(t: Tool) -> ToolOut:
    return ToolOut(
        id=t.id,
        name=t.name,
        display_name=t.display_name,
        description=t.description,
        owner_team=t.owner_team,
        source=t.source,
        risk=t.risk,
        permissions=list(t.permissions or []),
        destination=t.destination,
        created_at=t.created_at,
    )


async def _load_tool(db, principal: Principal, tool_id: uuid.UUID) -> Tool:
    tool = await db.get(Tool, tool_id)
    if tool is None or tool.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tool not found")
    return tool


@tools_router.get("", response_model=list[ToolOut])
async def list_tools(db: DbSession, principal: ToolRead) -> list[ToolOut]:
    rows = (
        await db.scalars(
            select(Tool)
            .where(Tool.organization_id == principal.organization_id)
            .order_by(Tool.name)
        )
    ).all()
    return [_tool_out(t) for t in rows]


@tools_router.post("", response_model=ToolOut, status_code=status.HTTP_201_CREATED)
async def create_tool(body: ToolIn, db: DbSession, principal: ToolManage) -> ToolOut:
    dup = await db.scalar(
        select(Tool.id).where(
            Tool.organization_id == principal.organization_id, Tool.name == body.name
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "tool with this name already exists")
    tool = Tool(
        organization_id=principal.organization_id,
        name=body.name,
        display_name=body.display_name,
        description=body.description,
        owner_team=body.owner_team,
        source=body.source,
        risk=body.risk,
        permissions=[p.value for p in body.permissions],
        destination=body.destination,
    )
    db.add(tool)
    await db.flush()
    return _tool_out(tool)


@tools_router.get("/{tool_id}", response_model=ToolOut)
async def get_tool(tool_id: uuid.UUID, db: DbSession, principal: ToolRead) -> ToolOut:
    return _tool_out(await _load_tool(db, principal, tool_id))


@tools_router.patch("/{tool_id}", response_model=ToolOut)
async def update_tool(
    tool_id: uuid.UUID, body: ToolPatch, db: DbSession, principal: ToolManage
) -> ToolOut:
    tool = await _load_tool(db, principal, tool_id)
    data = body.model_dump(exclude_none=True)
    if "permissions" in data:
        data["permissions"] = [p.value if hasattr(p, "value") else p for p in data["permissions"]]
    for field, value in data.items():
        setattr(tool, field, value)
    await db.flush()
    return _tool_out(tool)


@tools_router.delete("/{tool_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tool(tool_id: uuid.UUID, db: DbSession, principal: ToolManage) -> Response:
    tool = await _load_tool(db, principal, tool_id)
    await db.delete(tool)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
