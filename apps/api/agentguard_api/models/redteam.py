"""Red-team platform — PRD §18–22, §44 (redteam_assessments, redteam_tests,
redteam_findings)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, UUIDMixin, enum_column, org_column
from .enums import (
    AssessmentProfile,
    AssessmentStatus,
    AttackCategory,
    Environment,
    FindingStatus,
    RiskSeverity,
)


class RedTeamAssessment(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "redteam_assessments"

    organization_id: Mapped[uuid.UUID] = org_column()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    environment: Mapped[Environment] = enum_column(Environment, nullable=False)
    profile: Mapped[AssessmentProfile] = enum_column(AssessmentProfile, nullable=False)
    status: Mapped[AssessmentStatus] = enum_column(
        AssessmentStatus, nullable=False, default=AssessmentStatus.queued
    )
    model: Mapped[str | None] = mapped_column(String(120))
    trigger: Mapped[str | None] = mapped_column(
        String(40)
    )  # deployment / model / prompt / ci / manual
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime | None] = mapped_column()
    completed_at: Mapped[datetime | None] = mapped_column()
    # {"critical": 4, "high": 19, "passed": 812, ...}
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    tests: Mapped[list[RedTeamTest]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class RedTeamTest(UUIDMixin, Base):
    """One attack attempt. Fields per PRD §20."""

    __tablename__ = "redteam_tests"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("redteam_assessments.id", ondelete="CASCADE"), index=True
    )
    attack_id: Mapped[str] = mapped_column(String(80), nullable=False)
    category: Mapped[AttackCategory] = enum_column(AttackCategory, nullable=False)
    technique: Mapped[str] = mapped_column(String(160), nullable=False)
    input_summary: Mapped[str | None] = mapped_column(Text)
    expected_behavior: Mapped[str | None] = mapped_column(Text)
    observed_behavior: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[RiskSeverity] = enum_column(
        RiskSeverity, nullable=False, default=RiskSeverity.info
    )
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    evidence_uri: Mapped[str | None] = mapped_column(String(400))  # s3://... (PRD §47)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    assessment: Mapped[RedTeamAssessment] = relationship(back_populates="tests")


class RedTeamFinding(UUIDMixin, TimestampMixin, Base):
    """PRD §22 — a managed finding with lifecycle + actions."""

    __tablename__ = "redteam_findings"

    organization_id: Mapped[uuid.UUID] = org_column()
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("redteam_assessments.id", ondelete="SET NULL")
    )
    test_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("redteam_tests.id", ondelete="SET NULL")
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    tool_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tools.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    category: Mapped[AttackCategory] = enum_column(AttackCategory, nullable=False)
    severity: Mapped[RiskSeverity] = enum_column(RiskSeverity, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[FindingStatus] = enum_column(
        FindingStatus, nullable=False, default=FindingStatus.open
    )
    recommendation: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    resolution_note: Mapped[str | None] = mapped_column(Text)
