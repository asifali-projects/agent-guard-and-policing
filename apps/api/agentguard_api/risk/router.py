"""Risk endpoint — /v1/risk (PRD §26, feeds §14 agent security posture)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..dlp.service import scan_payload
from ..models import Agent, AgentIdentity, Tool
from .engine import assess
from .schemas import RiskAssessment

router = APIRouter(prefix="/v1/risk", tags=["risk"])

AnalyticsDep = Annotated[Principal, Depends(require_permission("analytics.read"))]


class RiskScoreIn(BaseModel):
    agent_id: uuid.UUID
    tool: str
    action: str = "execute"
    parameters: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)


@router.post("/score", response_model=RiskAssessment)
async def score(body: RiskScoreIn, db: DbSession, principal: AnalyticsDep) -> RiskAssessment:
    agent = await db.get(Agent, body.agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    identity = await db.scalar(select(AgentIdentity).where(AgentIdentity.agent_id == agent.id))
    tool = await db.scalar(
        select(Tool).where(
            Tool.organization_id == principal.organization_id, Tool.name == body.tool
        )
    )
    dlp = await scan_payload(db, principal.organization_id, body.parameters)
    return await assess(
        db,
        organization_id=principal.organization_id,
        agent=agent,
        identity=identity,
        tool=tool,
        tool_name=body.tool,
        parameters=body.parameters,
        context=body.context,
        dlp=dlp,
    )
