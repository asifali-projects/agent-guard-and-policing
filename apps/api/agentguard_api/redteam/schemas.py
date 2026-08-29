"""Red-team API models (PRD §18–22)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from ..models.enums import (
    AssessmentProfile,
    AssessmentStatus,
    AttackCategory,
    Environment,
    FindingStatus,
    RiskSeverity,
)


class AssessmentCreate(BaseModel):
    agent_id: uuid.UUID
    profile: AssessmentProfile = AssessmentProfile.standard
    environment: Environment | None = None
    model: str | None = None
    trigger: str = Field(default="manual", max_length=40)
    categories: list[AttackCategory] | None = None
    technique_ids: list[str] | None = None


class AssessmentOut(BaseModel):
    id: uuid.UUID
    agent_id: uuid.UUID
    environment: Environment
    profile: AssessmentProfile
    status: AssessmentStatus
    trigger: str | None
    model: str | None
    summary: dict
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class TestOut(BaseModel):
    id: uuid.UUID
    attack_id: str
    category: AttackCategory
    technique: str
    input_summary: str | None
    expected_behavior: str | None
    observed_behavior: str | None
    severity: RiskSeverity
    passed: bool


class FindingOut(BaseModel):
    id: uuid.UUID
    assessment_id: uuid.UUID | None
    agent_id: uuid.UUID
    tool_id: uuid.UUID | None
    title: str
    category: AttackCategory
    severity: RiskSeverity
    risk_score: int | None
    status: FindingStatus
    recommendation: str | None
    owner_id: uuid.UUID | None
    resolution_note: str | None
    created_at: datetime
    updated_at: datetime


class SuppressIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class AssignIn(BaseModel):
    owner_id: uuid.UUID


class RetestOut(BaseModel):
    finding_id: uuid.UUID
    status: FindingStatus
    passed: bool
    observed_behavior: str


class TechniqueOut(BaseModel):
    id: str
    category: AttackCategory
    name: str
    description: str
    base_severity: RiskSeverity
    defended: list[str]
