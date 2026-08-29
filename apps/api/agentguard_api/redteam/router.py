"""Red-team endpoints — /v1/redteam (PRD §18–22)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.exceptions import HTTPException
from sqlalchemy import func, select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import (
    Agent,
    Incident,
    RedTeamAssessment,
    RedTeamFinding,
    RedTeamTest,
)
from ..models.enums import (
    ActorType,
    AssessmentStatus,
    AttackCategory,
    FindingStatus,
    RiskSeverity,
)
from ..policies import service as policy_service
from ..runtime.core import core_decision
from . import catalog
from .evaluator import judge
from .runner import run_assessment
from .schemas import (
    AssessmentCreate,
    AssessmentOut,
    AssignIn,
    FindingOut,
    RetestOut,
    SuppressIn,
    TechniqueOut,
    TestOut,
)

router = APIRouter(prefix="/v1/redteam", tags=["red-team"])

RunDep = Annotated[Principal, Depends(require_permission("redteam.run"))]
ReadDep = Annotated[Principal, Depends(require_permission("redteam.read"))]
FindingRead = Annotated[Principal, Depends(require_permission("finding.read"))]
FindingManage = Annotated[Principal, Depends(require_permission("finding.manage"))]


def _assessment_out(a: RedTeamAssessment) -> AssessmentOut:
    return AssessmentOut(
        id=a.id,
        agent_id=a.agent_id,
        environment=a.environment,
        profile=a.profile,
        status=a.status,
        trigger=a.trigger,
        model=a.model,
        summary=a.summary or {},
        started_at=a.started_at,
        completed_at=a.completed_at,
        created_at=a.created_at,
    )


def _finding_out(f: RedTeamFinding) -> FindingOut:
    return FindingOut(
        id=f.id,
        assessment_id=f.assessment_id,
        agent_id=f.agent_id,
        tool_id=f.tool_id,
        title=f.title,
        category=f.category,
        severity=f.severity,
        risk_score=f.risk_score,
        status=f.status,
        recommendation=f.recommendation,
        owner_id=f.owner_id,
        resolution_note=f.resolution_note,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


@router.get("/techniques", response_model=list[TechniqueOut])
async def list_techniques(principal: ReadDep) -> list[TechniqueOut]:
    return [
        TechniqueOut(
            id=t.id,
            category=t.category,
            name=t.name,
            description=t.description,
            base_severity=t.base_severity,
            defended=sorted(d.value.upper() for d in t.defended),
        )
        for t in catalog.TECHNIQUES
    ]


# --- assessments -------------------------------------------------------


@router.post("/assessments", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    body: AssessmentCreate, db: DbSession, principal: RunDep
) -> AssessmentOut:
    agent = await db.get(Agent, body.agent_id)
    if agent is None or agent.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")

    assessment = RedTeamAssessment(
        organization_id=principal.organization_id,
        agent_id=agent.id,
        environment=body.environment or agent.environment,
        profile=body.profile,
        status=AssessmentStatus.queued,
        model=body.model,
        trigger=body.trigger,
    )
    db.add(assessment)
    await db.flush()

    await run_assessment(
        db,
        assessment=assessment,
        categories=body.categories,
        technique_ids=body.technique_ids,
        actor_label=principal.actor_label,
        user_id=principal.user_id,
    )
    return _assessment_out(assessment)


@router.get("/assessments", response_model=list[AssessmentOut])
async def list_assessments(
    db: DbSession,
    principal: ReadDep,
    agent_id: uuid.UUID | None = None,
) -> list[AssessmentOut]:
    stmt = select(RedTeamAssessment).where(
        RedTeamAssessment.organization_id == principal.organization_id
    )
    if agent_id:
        stmt = stmt.where(RedTeamAssessment.agent_id == agent_id)
    stmt = stmt.order_by(RedTeamAssessment.created_at.desc())
    return [_assessment_out(a) for a in (await db.scalars(stmt)).all()]


async def _load_assessment(db, principal: Principal, aid: uuid.UUID) -> RedTeamAssessment:
    a = await db.get(RedTeamAssessment, aid)
    if a is None or a.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    return a


@router.get("/assessments/{assessment_id}", response_model=AssessmentOut)
async def get_assessment(
    assessment_id: uuid.UUID, db: DbSession, principal: ReadDep
) -> AssessmentOut:
    return _assessment_out(await _load_assessment(db, principal, assessment_id))


@router.get("/assessments/{assessment_id}/tests", response_model=list[TestOut])
async def list_tests(assessment_id: uuid.UUID, db: DbSession, principal: ReadDep) -> list[TestOut]:
    await _load_assessment(db, principal, assessment_id)
    rows = (
        await db.scalars(
            select(RedTeamTest)
            .where(RedTeamTest.assessment_id == assessment_id)
            .order_by(RedTeamTest.attack_id)
        )
    ).all()
    return [
        TestOut(
            id=t.id,
            attack_id=t.attack_id,
            category=t.category,
            technique=t.technique,
            input_summary=t.input_summary,
            expected_behavior=t.expected_behavior,
            observed_behavior=t.observed_behavior,
            severity=t.severity,
            passed=t.passed,
        )
        for t in rows
    ]


# --- findings (PRD §22) ---------------------------------------------


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    db: DbSession,
    principal: FindingRead,
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    severity: RiskSeverity | None = None,
    agent_id: uuid.UUID | None = None,
    category: AttackCategory | None = None,
) -> list[FindingOut]:
    stmt = select(RedTeamFinding).where(RedTeamFinding.organization_id == principal.organization_id)
    if status_filter:
        stmt = stmt.where(RedTeamFinding.status == status_filter)
    if severity:
        stmt = stmt.where(RedTeamFinding.severity == severity)
    if agent_id:
        stmt = stmt.where(RedTeamFinding.agent_id == agent_id)
    if category:
        stmt = stmt.where(RedTeamFinding.category == category)
    stmt = stmt.order_by(RedTeamFinding.created_at.desc())
    return [_finding_out(f) for f in (await db.scalars(stmt)).all()]


async def _load_finding(db, principal: Principal, fid: uuid.UUID) -> RedTeamFinding:
    f = await db.get(RedTeamFinding, fid)
    if f is None or f.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return f


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: uuid.UUID, db: DbSession, principal: FindingRead) -> FindingOut:
    return _finding_out(await _load_finding(db, principal, finding_id))


async def _finding_audit(db, principal: Principal, f: RedTeamFinding, action: str) -> None:
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action=action,
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        agent_id=f.agent_id,
        metadata={"finding_id": str(f.id), "title": f.title},
    )


@router.post("/findings/{finding_id}/suppress", response_model=FindingOut)
async def suppress(
    finding_id: uuid.UUID, body: SuppressIn, db: DbSession, principal: FindingManage
) -> FindingOut:
    f = await _load_finding(db, principal, finding_id)
    f.status = FindingStatus.suppressed
    f.resolution_note = body.reason
    await _finding_audit(db, principal, f, "finding.suppress")
    await db.refresh(f)
    return _finding_out(f)


@router.post("/findings/{finding_id}/false-positive", response_model=FindingOut)
async def false_positive(
    finding_id: uuid.UUID, db: DbSession, principal: FindingManage
) -> FindingOut:
    f = await _load_finding(db, principal, finding_id)
    f.status = FindingStatus.false_positive
    await _finding_audit(db, principal, f, "finding.false_positive")
    await db.refresh(f)
    return _finding_out(f)


@router.post("/findings/{finding_id}/assign", response_model=FindingOut)
async def assign(
    finding_id: uuid.UUID, body: AssignIn, db: DbSession, principal: FindingManage
) -> FindingOut:
    f = await _load_finding(db, principal, finding_id)
    f.owner_id = body.owner_id
    await _finding_audit(db, principal, f, "finding.assign")
    await db.refresh(f)
    return _finding_out(f)


@router.post("/findings/{finding_id}/retest", response_model=RetestOut)
async def retest(finding_id: uuid.UUID, db: DbSession, principal: FindingManage) -> RetestOut:
    f = await _load_finding(db, principal, finding_id)
    technique = catalog.technique_by_name(f.title.split(" — ")[0])
    if technique is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "finding has no known technique")
    agent = await db.get(Agent, f.agent_id)
    variant = technique.variants[0]
    core = await core_decision(
        db,
        organization_id=principal.organization_id,
        agent=agent,
        tool=variant.tool,
        action=variant.action,
        parameters=variant.parameters,
        context=variant.context,
    )
    verdict = judge(technique, core.decision, core)
    if verdict.passed:
        f.status = FindingStatus.resolved
        f.resolution_note = f"Retest passed: {verdict.observed_behavior}"
    else:
        f.status = FindingStatus.open
        f.severity = verdict.severity
        f.risk_score = core.risk.risk_score if core.risk else f.risk_score
    await _finding_audit(db, principal, f, "finding.retest")
    return RetestOut(
        finding_id=f.id,
        status=f.status,
        passed=verdict.passed,
        observed_behavior=verdict.observed_behavior,
    )


@router.post("/findings/{finding_id}/policy", status_code=status.HTTP_201_CREATED)
async def create_remediation_policy(
    finding_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("finding.manage", "policy.manage"))],
) -> dict:
    f = await _load_finding(db, principal, finding_id)
    technique = catalog.technique_by_name(f.title.split(" — ")[0])
    if technique is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "finding has no known technique")
    spec = catalog.remediation_spec(technique)
    key = f"RT-{technique.id.upper().replace('.', '-')[:36]}"
    try:
        policy = await policy_service.create_policy(
            db,
            organization_id=principal.organization_id,
            created_by_id=principal.user_id,
            key=key,
            name=f"Remediate: {technique.name}",
            description=technique.recommendation,
            enabled=True,
            priority=50,
            spec=spec,
        )
    except policy_service.PolicyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    from ..models import PolicyBinding
    from ..models.enums import PolicyScopeType

    await policy_service.add_binding(
        db, policy, PolicyBinding(scope_type=PolicyScopeType.organization)
    )
    await _finding_audit(db, principal, f, "finding.create_policy")
    return {"policy_id": str(policy.id), "key": policy.key, "spec": spec}


@router.post("/findings/{finding_id}/incident", status_code=status.HTTP_201_CREATED)
async def create_incident(
    finding_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[
        Principal, Depends(require_permission("finding.manage", "incident.manage"))
    ],
) -> dict:
    f = await _load_finding(db, principal, finding_id)
    count = await db.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.organization_id == principal.organization_id)
    )
    incident = Incident(
        organization_id=principal.organization_id,
        key=f"INC-{(count or 0) + 1:04d}",
        title=f"Red-team finding: {f.title}",
        severity=f.severity if f.severity != RiskSeverity.info else RiskSeverity.medium,
        agent_id=f.agent_id,
        opened_by_id=principal.user_id,
        summary=f.recommendation,
    )
    db.add(incident)
    await db.flush()
    await _finding_audit(db, principal, f, "finding.create_incident")
    return {"incident_id": str(incident.id), "key": incident.key}
