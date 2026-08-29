"""Attack planner + sandbox executor + finding writer (PRD §20)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..billing import meter
from ..events import bus
from ..models import Agent, RedTeamAssessment, RedTeamFinding, RedTeamTest, Tool
from ..models.enums import (
    ActorType,
    AssessmentStatus,
    AttackCategory,
    FindingStatus,
    RiskSeverity,
)
from ..runtime.core import core_decision
from .catalog import Technique, techniques_for, variant_budget
from .evaluator import judge

_OPEN = (FindingStatus.open, FindingStatus.triaged, FindingStatus.retest)
_SEV_RANK = {
    RiskSeverity.info: 0,
    RiskSeverity.low: 1,
    RiskSeverity.medium: 2,
    RiskSeverity.high: 3,
    RiskSeverity.critical: 4,
}


async def _tool_id(session: AsyncSession, org_id: uuid.UUID, name: str) -> uuid.UUID | None:
    return await session.scalar(
        select(Tool.id).where(Tool.organization_id == org_id, Tool.name == name)
    )


async def _upsert_finding(
    session: AsyncSession,
    *,
    assessment: RedTeamAssessment,
    agent_id: uuid.UUID,
    technique: Technique,
    test: RedTeamTest,
    severity: RiskSeverity,
    risk_score: int,
) -> RedTeamFinding:
    title = f"{technique.name} — not defended"
    existing = await session.scalar(
        select(RedTeamFinding).where(
            RedTeamFinding.organization_id == assessment.organization_id,
            RedTeamFinding.agent_id == agent_id,
            RedTeamFinding.title == title,
            RedTeamFinding.status.in_(_OPEN),
        )
    )
    if existing is not None:
        existing.assessment_id = assessment.id
        existing.test_id = test.id
        existing.severity = severity
        existing.risk_score = risk_score
        existing.status = FindingStatus.open
        return existing

    finding = RedTeamFinding(
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        test_id=test.id,
        agent_id=agent_id,
        tool_id=await _tool_id(session, assessment.organization_id, technique.variants[0].tool),
        title=title,
        category=technique.category,
        severity=severity,
        risk_score=risk_score,
        status=FindingStatus.open,
        recommendation=technique.recommendation,
    )
    session.add(finding)
    return finding


async def run_assessment(
    session: AsyncSession,
    *,
    assessment: RedTeamAssessment,
    categories: list[AttackCategory] | None = None,
    technique_ids: list[str] | None = None,
    actor_label: str | None = None,
    user_id: uuid.UUID | None = None,
) -> dict:
    agent = await session.get(Agent, assessment.agent_id)
    assert agent is not None

    assessment.status = AssessmentStatus.running
    assessment.started_at = datetime.now(UTC)
    await session.flush()

    techniques = techniques_for(
        assessment.profile, categories=categories, technique_ids=technique_ids
    )
    budget = variant_budget(assessment.profile)

    counts = {"total": 0, "passed": 0, "failed": 0}
    sev_counts = {s.value: 0 for s in RiskSeverity}
    findings_made = 0

    for technique in techniques:
        worst: tuple[int, RedTeamTest, int] | None = None  # (sev_rank, test, risk_score)
        for n, variant in enumerate(technique.variants[:budget], start=1):
            core = await core_decision(
                session,
                organization_id=assessment.organization_id,
                agent=agent,
                tool=variant.tool,
                action=variant.action,
                parameters=variant.parameters,
                context=variant.context,
            )
            verdict = judge(technique, core.decision, core)
            test = RedTeamTest(
                assessment_id=assessment.id,
                attack_id=f"{technique.id}#{n}",
                category=technique.category,
                technique=technique.name,
                input_summary=variant.note or f"{variant.tool} {variant.parameters}",
                expected_behavior=verdict.expected_behavior,
                observed_behavior=verdict.observed_behavior,
                severity=verdict.severity,
                passed=verdict.passed,
            )
            session.add(test)
            await session.flush()

            counts["total"] += 1
            counts["passed" if verdict.passed else "failed"] += 1
            if not verdict.passed:
                sev_counts[verdict.severity.value] += 1
                rank = _SEV_RANK[verdict.severity]
                risk_score = core.risk.risk_score if core.risk else 0
                if worst is None or rank > worst[0]:
                    worst = (rank, test, risk_score)

        if worst is not None:
            await _upsert_finding(
                session,
                assessment=assessment,
                agent_id=agent.id,
                technique=technique,
                test=worst[1],
                severity=list(_SEV_RANK)[worst[0]],
                risk_score=worst[2],
            )
            findings_made += 1

    summary = {
        **counts,
        "by_severity": sev_counts,
        "findings": findings_made,
        "config": {
            "profile": assessment.profile.value,
            "categories": [c.value for c in categories] if categories else None,
            "technique_ids": technique_ids,
        },
    }
    assessment.summary = summary
    assessment.status = AssessmentStatus.completed
    assessment.completed_at = datetime.now(UTC)
    await session.flush()

    await audit_log.record(
        session,
        organization_id=assessment.organization_id,
        action="redteam.completed",
        actor_type=ActorType.user if user_id else ActorType.system,
        user_id=user_id,
        actor_label=actor_label,
        agent_id=agent.id,
        metadata={"assessment_id": str(assessment.id), **counts, "findings": findings_made},
    )
    await meter("redteam_tests", assessment.organization_id, counts["total"])
    await bus.publish(
        session,
        organization_id=assessment.organization_id,
        event_type="redteam.completed",
        payload={
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "profile": assessment.profile.value,
            "findings": findings_made,
            **counts,
            "by_severity": sev_counts,
        },
    )
    return summary
