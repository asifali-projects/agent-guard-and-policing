"""Incident + threat endpoints — /v1/incidents, /v1/threats (PRD §30)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from fastapi.exceptions import HTTPException
from sqlalchemy import select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import Incident, IncidentEvent, Threat
from ..models.enums import IncidentStatus, RiskSeverity, ThreatStatus
from . import service
from .schemas import (
    ActionIn,
    IncidentCreate,
    IncidentDetail,
    IncidentEventOut,
    IncidentOut,
    ThreatOut,
    TransitionIn,
)

router = APIRouter(tags=["incidents"])

IncRead = Annotated[Principal, Depends(require_permission("incident.read"))]
IncManage = Annotated[Principal, Depends(require_permission("incident.manage"))]
ThreatRead = Annotated[Principal, Depends(require_permission("threat.read"))]


def _incident_out(i: Incident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        key=i.key,
        title=i.title,
        severity=i.severity,
        status=i.status,
        agent_id=i.agent_id,
        summary=i.summary,
        opened_at=i.opened_at,
        contained_at=i.contained_at,
        resolved_at=i.resolved_at,
        closed_at=i.closed_at,
        created_at=i.created_at,
    )


# --- threats ---------------------------------------------------------


@router.get("/v1/threats", response_model=list[ThreatOut])
async def list_threats(
    db: DbSession,
    principal: ThreatRead,
    status_filter: Annotated[ThreatStatus | None, Query(alias="status")] = None,
) -> list[ThreatOut]:
    stmt = select(Threat).where(Threat.organization_id == principal.organization_id)
    if status_filter:
        stmt = stmt.where(Threat.status == status_filter)
    stmt = stmt.order_by(Threat.detected_at.desc())
    return [
        ThreatOut(
            id=t.id,
            agent_id=t.agent_id,
            kind=t.kind,
            severity=t.severity,
            risk_score=t.risk_score,
            status=t.status,
            description=t.description,
            source=t.source,
            context=t.context,
            detected_at=t.detected_at,
            incident_id=t.incident_id,
        )
        for t in (await db.scalars(stmt)).all()
    ]


@router.post("/v1/threats/{threat_id}/resolve", response_model=ThreatOut)
async def resolve_threat(threat_id: uuid.UUID, db: DbSession, principal: IncManage) -> ThreatOut:
    t = await db.get(Threat, threat_id)
    if t is None or t.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "threat not found")
    t.status = ThreatStatus.resolved
    return ThreatOut(
        id=t.id,
        agent_id=t.agent_id,
        kind=t.kind,
        severity=t.severity,
        risk_score=t.risk_score,
        status=t.status,
        description=t.description,
        source=t.source,
        context=t.context,
        detected_at=t.detected_at,
        incident_id=t.incident_id,
    )


# --- incidents ----------------------------------------------------


@router.get("/v1/incidents", response_model=list[IncidentOut])
async def list_incidents(
    db: DbSession,
    principal: IncRead,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: RiskSeverity | None = None,
) -> list[IncidentOut]:
    stmt = select(Incident).where(Incident.organization_id == principal.organization_id)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    stmt = stmt.order_by(Incident.opened_at.desc())
    return [_incident_out(i) for i in (await db.scalars(stmt)).all()]


@router.post("/v1/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
async def create_incident(body: IncidentCreate, db: DbSession, principal: IncManage) -> IncidentOut:
    incident = Incident(
        organization_id=principal.organization_id,
        key=await service._next_key(db, principal.organization_id),
        title=body.title,
        severity=body.severity,
        status=IncidentStatus.detected,
        agent_id=body.agent_id,
        opened_by_id=principal.user_id,
        summary=body.summary,
    )
    db.add(incident)
    await db.flush()
    await service.add_event(session=db, incident=incident, kind="opened", message="Opened manually")
    return _incident_out(incident)


async def _load(db, principal: Principal, iid: uuid.UUID) -> Incident:
    i = await db.get(Incident, iid)
    if i is None or i.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return i


@router.get("/v1/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: uuid.UUID, db: DbSession, principal: IncRead) -> IncidentDetail:
    i = await _load(db, principal, incident_id)
    events = (
        await db.scalars(
            select(IncidentEvent)
            .where(IncidentEvent.incident_id == i.id)
            .order_by(IncidentEvent.created_at.asc())
        )
    ).all()
    return IncidentDetail(
        **_incident_out(i).model_dump(),
        events=[
            IncidentEventOut(
                id=e.id,
                kind=e.kind,
                actor_type=e.actor_type.value,
                actor_id=e.actor_id,
                message=e.message,
                data=e.data,
                created_at=e.created_at,
            )
            for e in events
        ],
    )


@router.post("/v1/incidents/{incident_id}/transition", response_model=IncidentOut)
async def transition_incident(
    incident_id: uuid.UUID, body: TransitionIn, db: DbSession, principal: IncManage
) -> IncidentOut:
    i = await _load(db, principal, incident_id)
    try:
        await service.transition(
            db, i, body.status, actor_id=principal.user_id, actor_label=principal.actor_label
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _incident_out(i)


@router.post("/v1/incidents/{incident_id}/actions")
async def incident_action(
    incident_id: uuid.UUID, body: ActionIn, db: DbSession, principal: IncManage
) -> dict:
    i = await _load(db, principal, incident_id)
    try:
        return await service.apply_action(
            db,
            i,
            body.action,
            tool=body.tool,
            actor_id=principal.user_id,
            actor_label=principal.actor_label,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
