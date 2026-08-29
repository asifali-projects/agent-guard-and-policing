"""Read-only capability library for the AI Security Analyst (PRD §35).

Every tool is a deterministic, organization-scoped query over the control plane.
Nothing here writes, and no tool can reach another tenant's data — `org_id` is
bound by the caller, never by the model.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    Agent,
    AgentIdentity,
    ApprovalRequest,
    AuditEvent,
    Incident,
    McpServer,
    Policy,
    RedTeamAssessment,
    RedTeamFinding,
    Threat,
)
from ..models import (
    Tool as ToolModel,
)
from ..models.enums import ApprovalStatus, Decision, FindingStatus, IncidentStatus, ThreatStatus

Runner = Callable[[AsyncSession, uuid.UUID, dict[str, Any]], Awaitable[dict[str, Any]]]

_OPEN_FINDINGS = (FindingStatus.open, FindingStatus.triaged, FindingStatus.retest)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    run: Runner

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "additionalProperties": False,
            },
        }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _limit(args: dict, default: int = 20, cap: int = 100) -> int:
    try:
        return max(1, min(int(args.get("limit", default)), cap))
    except (TypeError, ValueError):
        return default


async def _count(db: AsyncSession, model: Any, *conds: Any) -> int:
    return int(await db.scalar(select(func.count()).select_from(model).where(*conds)) or 0)


async def _resolve_agent(db: AsyncSession, org_id: uuid.UUID, ref: str | None) -> Agent | None:
    if not ref:
        return None
    try:
        by_id = await db.get(Agent, uuid.UUID(str(ref)))
        if by_id is not None and by_id.organization_id == org_id:
            return by_id
    except ValueError:
        pass
    return await db.scalar(
        select(Agent).where(
            Agent.organization_id == org_id, func.lower(Agent.name) == str(ref).lower()
        )
    )


# --- tools ------------------------------------------------------------


async def _security_overview(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    since = datetime.now(UTC) - timedelta(hours=24)
    fbase = (RedTeamFinding.organization_id == org, RedTeamFinding.status.in_(_OPEN_FINDINGS))
    sev = {}
    for name in ("critical", "high", "medium", "low"):
        sev[name] = await _count(db, RedTeamFinding, *fbase, RedTeamFinding.severity == name)
    actions = await _count(
        db,
        AuditEvent,
        AuditEvent.organization_id == org,
        AuditEvent.action == "runtime.evaluate",
        AuditEvent.occurred_at >= since,
    )
    blocked = await _count(
        db,
        AuditEvent,
        AuditEvent.organization_id == org,
        AuditEvent.action == "runtime.evaluate",
        AuditEvent.decision == Decision.deny,
        AuditEvent.occurred_at >= since,
    )
    penalty = sev["critical"] * 12 + sev["high"] * 6 + sev["medium"] * 2
    return {
        "agents": await _count(db, Agent, Agent.organization_id == org),
        "tools": await _count(db, ToolModel, ToolModel.organization_id == org),
        "mcp_servers": await _count(db, McpServer, McpServer.organization_id == org),
        "open_findings": sev,
        "open_incidents": await _count(
            db,
            Incident,
            Incident.organization_id == org,
            Incident.status.notin_([IncidentStatus.resolved, IncidentStatus.closed]),
        ),
        "open_threats": await _count(
            db, Threat, Threat.organization_id == org, Threat.status == ThreatStatus.open
        ),
        "approvals_pending": await _count(
            db,
            ApprovalRequest,
            ApprovalRequest.organization_id == org,
            ApprovalRequest.status == ApprovalStatus.pending,
        ),
        "runtime_actions_24h": actions,
        "runtime_blocked_24h": blocked,
        "security_score": max(0, min(100, 100 - penalty)),
    }


async def _list_agents(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    stmt = select(Agent).where(Agent.organization_id == org)
    if args.get("status"):
        stmt = stmt.where(Agent.status == str(args["status"]))
    stmt = stmt.order_by(Agent.risk_score.desc().nullslast()).limit(_limit(args, 50))
    rows = (await db.scalars(stmt)).all()
    return {
        "agents": [
            {
                "id": str(a.id),
                "name": a.name,
                "environment": a.environment.value,
                "framework": a.framework.value,
                "status": a.status.value,
                "risk_score": a.risk_score,
                "owner_team": a.owner_team,
            }
            for a in rows
        ]
    }


async def _get_agent(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    agent = await _resolve_agent(db, org, args.get("name") or args.get("agent") or args.get("id"))
    if agent is None:
        return {"error": f"no agent named {args.get('name') or args.get('agent')!r}"}
    identity = await db.scalar(select(AgentIdentity).where(AgentIdentity.agent_id == agent.id))
    assessments_run = await _count(db, RedTeamAssessment, RedTeamAssessment.agent_id == agent.id)
    latest = await db.scalar(
        select(RedTeamAssessment)
        .where(RedTeamAssessment.agent_id == agent.id)
        .order_by(RedTeamAssessment.created_at.desc())
        .limit(1)
    )
    open_findings = await _count(
        db,
        RedTeamFinding,
        RedTeamFinding.agent_id == agent.id,
        RedTeamFinding.status.in_(_OPEN_FINDINGS),
    )
    recent_incidents = (
        await db.scalars(
            select(Incident)
            .where(Incident.agent_id == agent.id)
            .order_by(Incident.opened_at.desc())
            .limit(5)
        )
    ).all()
    return {
        "id": str(agent.id),
        "name": agent.name,
        "environment": agent.environment.value,
        "framework": agent.framework.value,
        "model": agent.model,
        "status": agent.status.value,
        "risk_score": agent.risk_score,
        "fail_mode": agent.fail_mode.value,
        "owner_team": agent.owner_team,
        "description": agent.description,
        "identity": None
        if identity is None
        else {
            "identity": identity.identity,
            "trust_level": identity.trust_level.value,
            "owner": identity.owner,
        },
        "assessments_run": assessments_run,
        "latest_assessment": None
        if latest is None
        else {
            "status": latest.status.value,
            "summary": latest.summary,
            "at": _iso(latest.created_at),
        },
        "open_findings": open_findings,
        "recent_incidents": [
            {"key": i.key, "title": i.title, "severity": i.severity.value, "status": i.status.value}
            for i in recent_incidents
        ],
    }


async def _top_risky_agents(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    rows = (await db.scalars(select(Agent).where(Agent.organization_id == org))).all()
    counts = dict(
        (
            await db.execute(
                select(RedTeamFinding.agent_id, func.count())
                .where(
                    RedTeamFinding.organization_id == org,
                    RedTeamFinding.status.in_(_OPEN_FINDINGS),
                )
                .group_by(RedTeamFinding.agent_id)
            )
        ).all()
    )
    ranked = sorted(rows, key=lambda a: (-(a.risk_score or 0), -counts.get(a.id, 0)))[
        : _limit(args, 10)
    ]
    return {
        "agents": [
            {
                "name": a.name,
                "environment": a.environment.value,
                "risk_score": a.risk_score,
                "status": a.status.value,
                "open_findings": counts.get(a.id, 0),
            }
            for a in ranked
        ]
    }


async def _list_findings(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    stmt = select(RedTeamFinding).where(RedTeamFinding.organization_id == org)
    if args.get("status"):
        stmt = stmt.where(RedTeamFinding.status == str(args["status"]))
    else:
        stmt = stmt.where(RedTeamFinding.status.in_(_OPEN_FINDINGS))
    if args.get("severity"):
        stmt = stmt.where(RedTeamFinding.severity == str(args["severity"]))
    agent = await _resolve_agent(db, org, args.get("agent"))
    if agent is not None:
        stmt = stmt.where(RedTeamFinding.agent_id == agent.id)
    stmt = stmt.order_by(RedTeamFinding.created_at.desc()).limit(_limit(args, 25))
    rows = (await db.scalars(stmt)).all()
    names = await _agent_names(db, {r.agent_id for r in rows})
    return {
        "findings": [
            {
                "id": str(r.id),
                "title": r.title,
                "category": r.category.value,
                "severity": r.severity.value,
                "status": r.status.value,
                "agent": names.get(r.agent_id),
                "recommendation": r.recommendation,
            }
            for r in rows
        ]
    }


async def _list_incidents(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    stmt = select(Incident).where(Incident.organization_id == org)
    if args.get("status"):
        stmt = stmt.where(Incident.status == str(args["status"]))
    stmt = stmt.order_by(Incident.opened_at.desc()).limit(_limit(args, 25))
    rows = (await db.scalars(stmt)).all()
    names = await _agent_names(db, {r.agent_id for r in rows if r.agent_id})
    return {
        "incidents": [
            {
                "key": i.key,
                "title": i.title,
                "severity": i.severity.value,
                "status": i.status.value,
                "agent": names.get(i.agent_id),
                "opened_at": _iso(i.opened_at),
                "summary": i.summary,
            }
            for i in rows
        ]
    }


async def _list_threats(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    stmt = select(Threat).where(Threat.organization_id == org)
    if args.get("status"):
        stmt = stmt.where(Threat.status == str(args["status"]))
    stmt = stmt.order_by(Threat.detected_at.desc()).limit(_limit(args, 25))
    rows = (await db.scalars(stmt)).all()
    names = await _agent_names(db, {r.agent_id for r in rows if r.agent_id})
    return {
        "threats": [
            {
                "kind": t.kind,
                "severity": t.severity.value,
                "status": t.status.value,
                "agent": names.get(t.agent_id),
                "detected_at": _iso(t.detected_at),
                "description": t.description,
            }
            for t in rows
        ]
    }


async def _search_audit(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    try:
        hours = max(1, min(int(args.get("hours", 168)), 24 * 90))
    except (TypeError, ValueError):
        hours = 168
    since = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(AuditEvent).where(
        AuditEvent.organization_id == org, AuditEvent.occurred_at >= since
    )
    if args.get("action"):
        stmt = stmt.where(AuditEvent.action == str(args["action"]))
    if args.get("decision"):
        stmt = stmt.where(AuditEvent.decision == str(args["decision"]))
    if args.get("tool"):
        stmt = stmt.where(AuditEvent.tool == str(args["tool"]))
    agent = await _resolve_agent(db, org, args.get("agent"))
    if agent is not None:
        stmt = stmt.where(AuditEvent.agent_id == agent.id)
    stmt = stmt.order_by(AuditEvent.occurred_at.desc()).limit(_limit(args, 30))
    rows = (await db.scalars(stmt)).all()
    names = await _agent_names(db, {r.agent_id for r in rows if r.agent_id})
    return {
        "window_hours": hours,
        "events": [
            {
                "occurred_at": _iso(e.occurred_at),
                "action": e.action,
                "actor": e.actor_id,
                "agent": names.get(e.agent_id),
                "tool": e.tool,
                "decision": e.decision.value if e.decision else None,
                "policy_key": e.policy_key,
                "risk_score": e.risk_score,
                "trace_id": e.trace_id,
            }
            for e in rows
        ],
    }


async def _explain_decision(db: AsyncSession, org: uuid.UUID, args: dict) -> dict:
    trace_id = args.get("trace_id")
    stmt = select(AuditEvent).where(
        AuditEvent.organization_id == org, AuditEvent.action == "runtime.evaluate"
    )
    if trace_id:
        stmt = stmt.where(AuditEvent.trace_id == str(trace_id))
    else:
        stmt = stmt.where(AuditEvent.decision != Decision.allow)
    event = await db.scalar(stmt.order_by(AuditEvent.occurred_at.desc()).limit(1))
    if event is None:
        return {"error": "no matching runtime decision found"}
    names = await _agent_names(db, {event.agent_id} if event.agent_id else set())
    policy = None
    if event.policy_key:
        p = await db.scalar(
            select(Policy).where(Policy.organization_id == org, Policy.key == event.policy_key)
        )
        if p is not None:
            policy = {
                "key": p.key,
                "name": p.name,
                "description": p.description,
                "priority": p.priority,
                "spec": p.spec,
            }
    return {
        "occurred_at": _iso(event.occurred_at),
        "agent": names.get(event.agent_id),
        "tool": event.tool,
        "decision": event.decision.value if event.decision else None,
        "risk_score": event.risk_score,
        "policy_key": event.policy_key,
        "matched_policy": policy,
        "trace_id": event.trace_id,
        "metadata": event.metadata_,
    }


async def _agent_names(db: AsyncSession, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = (await db.execute(select(Agent.id, Agent.name).where(Agent.id.in_(ids)))).all()
    return {aid: name for aid, name in rows}


_STATUS = {"type": "string", "description": "optional exact status filter"}
_SEVERITY = {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]}
_AGENT = {"type": "string", "description": "agent name or id"}
_LIMIT = {"type": "integer", "description": "max rows (default varies, capped at 100)"}

TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool(
            "security_overview",
            "Portfolio snapshot: asset counts, open findings by severity, open "
            "incidents/threats, pending approvals, 24h runtime volume, security score.",
            {},
            _security_overview,
        ),
        Tool(
            "list_agents",
            "List agents in the organization, most risky first.",
            {"status": _STATUS, "limit": _LIMIT},
            _list_agents,
        ),
        Tool(
            "get_agent",
            "Full detail for one agent: risk, identity/trust, assessments, open "
            "findings, recent incidents.",
            {"name": _AGENT},
            _get_agent,
        ),
        Tool(
            "top_risky_agents",
            "Agents ranked by risk score with their open finding counts.",
            {"limit": _LIMIT},
            _top_risky_agents,
        ),
        Tool(
            "list_findings",
            "Red-team / security findings. Defaults to open findings.",
            {"status": _STATUS, "severity": _SEVERITY, "agent": _AGENT, "limit": _LIMIT},
            _list_findings,
        ),
        Tool(
            "list_incidents",
            "Incidents and their lifecycle status.",
            {"status": _STATUS, "limit": _LIMIT},
            _list_incidents,
        ),
        Tool(
            "list_threats",
            "Detected threats (behavioral anomalies, prompt injection, etc.).",
            {"status": _STATUS, "limit": _LIMIT},
            _list_threats,
        ),
        Tool(
            "search_audit",
            "Query the tamper-evident audit log. Payloads are stored as hashes, "
            "so results are safe to quote.",
            {
                "action": {"type": "string"},
                "decision": {
                    "type": "string",
                    "enum": ["allow", "deny", "approval", "redact", "rate_limit"],
                },
                "agent": _AGENT,
                "tool": {"type": "string"},
                "hours": {"type": "integer", "description": "look-back window, default 168"},
                "limit": _LIMIT,
            },
            _search_audit,
        ),
        Tool(
            "explain_decision",
            "Reconstruct why a runtime action was blocked/redacted: the audit row, "
            "the matched policy, and the risk score. Give a trace_id or omit it for "
            "the most recent non-allow decision.",
            {"trace_id": {"type": "string"}},
            _explain_decision,
        ),
    ]
}


async def run_tool(
    db: AsyncSession, org_id: uuid.UUID, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}"}
    return await tool.run(db, org_id, arguments or {})
