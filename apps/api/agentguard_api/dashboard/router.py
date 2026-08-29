"""Dashboard summary endpoint — /v1/dashboard (PRD §11)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import (
    Agent,
    ApprovalRequest,
    AuditEvent,
    McpServer,
    RedTeamFinding,
    Tool,
)
from ..models.enums import ApprovalStatus, Decision, FindingStatus, RiskSeverity

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])

AnalyticsDep = Annotated[Principal, Depends(require_permission("analytics.read"))]

_OPEN = (FindingStatus.open, FindingStatus.triaged, FindingStatus.retest)


class Assets(BaseModel):
    agents: int
    mcp_servers: int
    tools: int


class Threats(BaseModel):
    critical: int
    high: int
    medium: int


class Runtime(BaseModel):
    actions_24h: int
    blocked_24h: int
    approvals_pending: int


class RiskyAgent(BaseModel):
    id: str
    name: str
    risk_score: int | None
    open_findings: int


class DashboardSummary(BaseModel):
    security_score: int
    assets: Assets
    threats: Threats
    runtime: Runtime
    top_risky_agents: list[RiskyAgent]


async def _count(db, model, *conds) -> int:
    return await db.scalar(select(func.count()).select_from(model).where(*conds)) or 0


@router.get("/summary", response_model=DashboardSummary)
async def summary(db: DbSession, principal: AnalyticsDep) -> DashboardSummary:
    org = principal.organization_id
    since = datetime.now(UTC) - timedelta(hours=24)

    assets = Assets(
        agents=await _count(db, Agent, Agent.organization_id == org),
        mcp_servers=await _count(db, McpServer, McpServer.organization_id == org),
        tools=await _count(db, Tool, Tool.organization_id == org),
    )

    fbase = (RedTeamFinding.organization_id == org, RedTeamFinding.status.in_(_OPEN))
    threats = Threats(
        critical=await _count(
            db, RedTeamFinding, *fbase, RedTeamFinding.severity == RiskSeverity.critical
        ),
        high=await _count(db, RedTeamFinding, *fbase, RedTeamFinding.severity == RiskSeverity.high),
        medium=await _count(
            db, RedTeamFinding, *fbase, RedTeamFinding.severity == RiskSeverity.medium
        ),
    )

    runtime = Runtime(
        actions_24h=await _count(
            db,
            AuditEvent,
            AuditEvent.organization_id == org,
            AuditEvent.action == "runtime.evaluate",
            AuditEvent.occurred_at >= since,
        ),
        blocked_24h=await _count(
            db,
            AuditEvent,
            AuditEvent.organization_id == org,
            AuditEvent.action == "runtime.evaluate",
            AuditEvent.decision == Decision.deny,
            AuditEvent.occurred_at >= since,
        ),
        approvals_pending=await _count(
            db,
            ApprovalRequest,
            ApprovalRequest.organization_id == org,
            ApprovalRequest.status == ApprovalStatus.pending,
        ),
    )

    agent_rows = (await db.scalars(select(Agent).where(Agent.organization_id == org))).all()
    finding_counts = dict(
        (
            await db.execute(
                select(RedTeamFinding.agent_id, func.count())
                .where(*fbase)
                .group_by(RedTeamFinding.agent_id)
            )
        ).all()
    )
    risky = sorted(
        (
            RiskyAgent(
                id=str(a.id),
                name=a.name,
                risk_score=a.risk_score,
                open_findings=finding_counts.get(a.id, 0),
            )
            for a in agent_rows
        ),
        key=lambda r: (-(r.risk_score or 0), -r.open_findings),
    )[:5]

    # Security score: start at 100, subtract weighted open findings, floor 0.
    penalty = threats.critical * 12 + threats.high * 6 + threats.medium * 2
    security_score = max(0, min(100, 100 - penalty))

    return DashboardSummary(
        security_score=security_score,
        assets=assets,
        threats=threats,
        runtime=runtime,
        top_risky_agents=risky,
    )
