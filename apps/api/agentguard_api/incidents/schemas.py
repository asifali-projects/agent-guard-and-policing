"""Incident + threat API models (PRD §30)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from ..models.enums import IncidentStatus, RiskSeverity, ThreatStatus


class ThreatOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID | None
    kind: str
    severity: RiskSeverity
    risk_score: int | None
    status: ThreatStatus
    description: str | None
    source: str | None
    context: dict
    detected_at: datetime
    incident_id: uuid.UUID | None


class IncidentEventOut(BaseModel):
    id: uuid.UUID
    kind: str
    actor_type: str
    actor_id: str | None
    message: str | None
    data: dict
    created_at: datetime


class IncidentOut(BaseModel):
    id: uuid.UUID
    key: str
    title: str
    severity: RiskSeverity
    status: IncidentStatus
    agent_id: uuid.UUID | None
    summary: str | None
    opened_at: datetime
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime


class IncidentDetail(IncidentOut):
    events: list[IncidentEventOut]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=2, max_length=240)
    severity: RiskSeverity = RiskSeverity.medium
    agent_id: uuid.UUID | None = None
    summary: str | None = None


class TransitionIn(BaseModel):
    status: IncidentStatus


class ActionIn(BaseModel):
    action: str = Field(pattern="^(pause_agent|resume_agent|block_tool|notify_security)$")
    tool: str | None = None
