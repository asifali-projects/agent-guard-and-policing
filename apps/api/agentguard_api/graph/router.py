"""Agent graph + blast radius — /v1/agents/{id}/graph|blast-radius (PRD §31–32)."""

from __future__ import annotations

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..detection.profile import load_profile
from ..models import Agent, AgentTool, McpServer, Tool
from ..models.enums import RiskSeverity

router = APIRouter(prefix="/v1/agents/{agent_id}", tags=["graph"])

AnalyticsDep = Annotated[Principal, Depends(require_permission("analytics.read"))]

_DB_RE = re.compile(r"(?i)\b(db|database|sql|postgres|mysql|table|query|export)\b")
_API_RE = re.compile(r"(?i)\b(api|http|rest|call|webhook|fetch|request)\b")


class Node(BaseModel):
    id: str
    type: str  # agent | tool | destination | data | mcp
    label: str
    meta: dict = {}


class Edge(BaseModel):
    source: str
    target: str
    kind: str


class GraphOut(BaseModel):
    nodes: list[Node]
    edges: list[Edge]


class BlastRadius(BaseModel):
    agent: str
    tools: int
    databases: int
    apis: int
    mcp_servers: int
    external_destinations: list[str]
    data_classifications: list[str]
    potential_impact: str
    detail: dict


async def _load_agent(db, principal: Principal, agent_id: uuid.UUID) -> Agent:
    a = await db.get(Agent, agent_id)
    if a is None or a.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    return a


async def _reachable(db, principal: Principal, agent: Agent):
    """Return (tool_names, tool_rows_by_name, destinations, classifications, mcp_rows)."""
    profile = await load_profile(db, agent.id)
    tool_names: set[str] = set(profile.tool_counts.keys()) if profile else set()
    classifications: set[str] = set(profile.classifications) if profile else set()
    destinations: set[str] = set(profile.destinations) if profile else set()

    granted = (
        await db.scalars(select(AgentTool.tool_id).where(AgentTool.agent_id == agent.id))
    ).all()
    tool_rows = (
        await db.scalars(select(Tool).where(Tool.organization_id == principal.organization_id))
    ).all()
    by_name = {t.name: t for t in tool_rows}
    by_id = {t.id: t for t in tool_rows}
    for tid in granted:
        if tid in by_id:
            tool_names.add(by_id[tid].name)
    for name in list(tool_names):
        t = by_name.get(name)
        if t and t.destination:
            destinations.add(t.destination)

    mcp_rows = (
        await db.scalars(
            select(McpServer).where(McpServer.organization_id == principal.organization_id)
        )
    ).all()
    return tool_names, by_name, destinations, classifications, mcp_rows


@router.get("/graph", response_model=GraphOut)
async def agent_graph(agent_id: uuid.UUID, db: DbSession, principal: AnalyticsDep) -> GraphOut:
    agent = await _load_agent(db, principal, agent_id)
    tool_names, by_name, destinations, classifications, mcp_rows = await _reachable(
        db, principal, agent
    )

    nodes: list[Node] = [
        Node(id="agent", type="agent", label=agent.name, meta={"risk": agent.risk_score})
    ]
    edges: list[Edge] = []

    for name in sorted(tool_names):
        t = by_name.get(name)
        nid = f"tool:{name}"
        nodes.append(
            Node(id=nid, type="tool", label=name, meta={"risk": t.risk.value if t else "unknown"})
        )
        edges.append(Edge(source="agent", target=nid, kind="calls"))
        if t and t.destination:
            dnid = f"dest:{t.destination}"
            if not any(n.id == dnid for n in nodes):
                nodes.append(Node(id=dnid, type="destination", label=t.destination))
            edges.append(Edge(source=nid, target=dnid, kind="sends-to"))

    for dest in sorted(destinations):
        dnid = f"dest:{dest}"
        if not any(n.id == dnid for n in nodes):
            nodes.append(Node(id=dnid, type="destination", label=dest))
            edges.append(Edge(source="agent", target=dnid, kind="observed"))

    for c in sorted(classifications):
        cnid = f"data:{c}"
        nodes.append(Node(id=cnid, type="data", label=f"{c} data"))
        edges.append(Edge(source="agent", target=cnid, kind="handles"))

    for m in mcp_rows:
        mnid = f"mcp:{m.id}"
        nodes.append(Node(id=mnid, type="mcp", label=m.name, meta={"status": m.status.value}))
        edges.append(Edge(source="agent", target=mnid, kind="may-use"))

    return GraphOut(nodes=nodes, edges=edges)


@router.get("/blast-radius", response_model=BlastRadius)
async def blast_radius(agent_id: uuid.UUID, db: DbSession, principal: AnalyticsDep) -> BlastRadius:
    agent = await _load_agent(db, principal, agent_id)
    tool_names, by_name, destinations, classifications, mcp_rows = await _reachable(
        db, principal, agent
    )

    databases = sum(1 for n in tool_names if _DB_RE.search(n))
    apis = sum(1 for n in tool_names if _API_RE.search(n) and not _DB_RE.search(n))
    external = sorted(
        d for d in destinations if d.lower() in {"external", "public", "third-party"} or "://" in d
    )
    crit_tools = sum(
        1
        for n in tool_names
        if (t := by_name.get(n)) and t.risk in {RiskSeverity.high, RiskSeverity.critical}
    )

    weight = (
        (agent.risk_score or 0)
        + crit_tools * 10
        + (30 if "restricted" in classifications else 0)
        + (20 if "confidential" in classifications else 0)
        + len(external) * 12
        + len(mcp_rows) * 5
    )
    impact = (
        "CRITICAL"
        if weight >= 120
        else "HIGH"
        if weight >= 75
        else "MEDIUM"
        if weight >= 35
        else "LOW"
    )

    return BlastRadius(
        agent=agent.name,
        tools=len(tool_names),
        databases=databases,
        apis=apis,
        mcp_servers=len(mcp_rows),
        external_destinations=external,
        data_classifications=sorted(classifications),
        potential_impact=impact,
        detail={
            "high_or_critical_tools": crit_tools,
            "agent_risk_score": agent.risk_score,
            "score": weight,
        },
    )
