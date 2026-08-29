"""Incident lifecycle + automatic response actions (PRD §30)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..detection.anomaly import AnomalyResult
from ..events import bus
from ..models import Agent, Incident, IncidentEvent, Policy, PolicyBinding, Threat
from ..models.enums import (
    ActorType,
    AgentStatus,
    IncidentStatus,
    PolicyScopeType,
    RiskSeverity,
    ThreatStatus,
)
from ..runtime.loader import bump_version

_AUTO_INCIDENT_AT = 85
_DEDUPE_WINDOW = timedelta(hours=1)

# status -> allowed next statuses
_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.detected: {
        IncidentStatus.investigating,
        IncidentStatus.contained,
        IncidentStatus.closed,
    },
    IncidentStatus.investigating: {
        IncidentStatus.contained,
        IncidentStatus.resolved,
        IncidentStatus.closed,
    },
    IncidentStatus.contained: {IncidentStatus.resolved, IncidentStatus.closed},
    IncidentStatus.resolved: {IncidentStatus.closed, IncidentStatus.investigating},
    IncidentStatus.closed: set(),
}


def _severity_from_score(score: int) -> RiskSeverity:
    if score >= 85:
        return RiskSeverity.critical
    if score >= 65:
        return RiskSeverity.high
    if score >= 40:
        return RiskSeverity.medium
    return RiskSeverity.low


async def _next_key(session: AsyncSession, org_id: uuid.UUID) -> str:
    n = await session.scalar(
        select(func.count()).select_from(Incident).where(Incident.organization_id == org_id)
    )
    return f"INC-{(n or 0) + 1:04d}"


async def add_event(
    *,
    session: AsyncSession,
    incident: Incident,
    kind: str,
    message: str,
    actor_type: ActorType = ActorType.system,
    actor_id: str | None = None,
    data: dict | None = None,
) -> IncidentEvent:
    ev = IncidentEvent(
        incident_id=incident.id,
        kind=kind,
        actor_type=actor_type,
        actor_id=actor_id,
        message=message,
        data=data or {},
    )
    session.add(ev)
    await session.flush()
    return ev


async def raise_behavioral_threat(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    agent_id: uuid.UUID,
    tool: str,
    anomaly: AnomalyResult,
    risk_score: int,
    request_id: str,
) -> Threat:
    since = datetime.now(UTC) - _DEDUPE_WINDOW
    existing = await session.scalar(
        select(Threat).where(
            Threat.organization_id == organization_id,
            Threat.agent_id == agent_id,
            Threat.kind == "behavioral_anomaly",
            Threat.status == ThreatStatus.open,
            Threat.detected_at >= since,
        )
    )
    severity = _severity_from_score(max(anomaly.score, risk_score))
    if existing is not None:
        existing.risk_score = max(existing.risk_score or 0, anomaly.score)
        existing.severity = severity
        existing.context = {"tool": tool, "signals": anomaly.signals, "request_id": request_id}
        return existing

    threat = Threat(
        organization_id=organization_id,
        agent_id=agent_id,
        kind="behavioral_anomaly",
        severity=severity,
        risk_score=anomaly.score,
        status=ThreatStatus.open,
        description=f"Behavioral anomaly on '{tool}': {anomaly.signals[0]}",
        source="detection.anomaly",
        context={"tool": tool, "signals": anomaly.signals, "request_id": request_id},
    )
    session.add(threat)
    await session.flush()

    await audit_log.record(
        session,
        organization_id=organization_id,
        action="threat.detected",
        actor_type=ActorType.system,
        agent_id=agent_id,
        risk_score=anomaly.score,
        request_id=request_id,
        metadata={"kind": "behavioral_anomaly", "signals": anomaly.signals},
    )
    await bus.publish(
        session,
        organization_id=organization_id,
        event_type="threat.detected",
        payload={
            "agent_id": str(agent_id),
            "kind": "behavioral_anomaly",
            "risk_score": anomaly.score,
            "severity": severity.value,
            "signals": anomaly.signals,
            "request_id": request_id,
        },
    )

    if max(anomaly.score, risk_score) >= _AUTO_INCIDENT_AT:
        incident = Incident(
            organization_id=organization_id,
            key=await _next_key(session, organization_id),
            title=f"Behavioral anomaly — {tool}",
            severity=severity,
            status=IncidentStatus.detected,
            agent_id=agent_id,
            summary=threat.description,
        )
        session.add(incident)
        await session.flush()
        threat.incident_id = incident.id
        await add_event(
            session=session,
            incident=incident,
            kind="opened",
            message="Auto-opened from a behavioral-anomaly threat",
            data={"threat_id": str(threat.id), "signals": anomaly.signals},
        )
        await bus.publish(
            session,
            organization_id=organization_id,
            event_type="incident.created",
            payload={
                "key": incident.key,
                "title": incident.title,
                "severity": severity.value,
                "agent_id": str(agent_id),
            },
        )
    return threat


async def transition(
    session: AsyncSession,
    incident: Incident,
    new_status: IncidentStatus,
    *,
    actor_id: uuid.UUID | None,
    actor_label: str | None,
) -> None:
    if new_status not in _TRANSITIONS.get(incident.status, set()):
        raise ValueError(f"cannot move incident from {incident.status.value} to {new_status.value}")
    now = datetime.now(UTC)
    incident.status = new_status
    if new_status == IncidentStatus.contained:
        incident.contained_at = now
    elif new_status == IncidentStatus.resolved:
        incident.resolved_at = now
    elif new_status == IncidentStatus.closed:
        incident.closed_at = now
    await add_event(
        session=session,
        incident=incident,
        kind="status_change",
        message=f"Status → {new_status.value}",
        actor_type=ActorType.user if actor_id else ActorType.system,
        actor_id=actor_label,
    )
    await bus.publish(
        session,
        organization_id=incident.organization_id,
        event_type="incident.updated",
        payload={"key": incident.key, "status": new_status.value, "title": incident.title},
    )


async def apply_action(
    session: AsyncSession,
    incident: Incident,
    action: str,
    *,
    tool: str | None,
    actor_id: uuid.UUID | None,
    actor_label: str | None,
) -> dict:
    org_id = incident.organization_id
    if action in {"pause_agent", "resume_agent"}:
        if incident.agent_id is None:
            raise ValueError("incident is not linked to an agent")
        agent = await session.get(Agent, incident.agent_id)
        agent.status = AgentStatus.paused if action == "pause_agent" else AgentStatus.healthy
        result = {"agent_status": agent.status.value}
    elif action == "block_tool":
        if not tool:
            raise ValueError("block_tool requires a tool name")
        key = f"IR-{incident.key}-{tool}".upper().replace(".", "-")[:40]
        dup = await session.scalar(
            select(Policy.id).where(Policy.organization_id == org_id, Policy.key == key)
        )
        if not dup:
            policy = Policy(
                organization_id=org_id,
                key=key,
                name=f"Incident block: {tool}",
                description=f"Auto-created by incident {incident.key}",
                enabled=True,
                priority=10,
                spec={"rules": [{"effect": "deny", "actions": [tool]}]},
            )
            session.add(policy)
            await session.flush()
            binding = PolicyBinding(
                policy_id=policy.id, organization_id=org_id, scope_type=PolicyScopeType.organization
            )
            session.add(binding)
            await session.flush()
            await bump_version(org_id)
        result = {"policy_key": key}
    elif action == "notify_security":
        # Delivered by the notifications worker in Step 9.
        result = {"queued": True}
    else:
        raise ValueError(f"unknown action '{action}'")

    await add_event(
        session=session,
        incident=incident,
        kind="action",
        message=f"Response action: {action}" + (f" ({tool})" if tool else ""),
        actor_type=ActorType.user if actor_id else ActorType.system,
        actor_id=actor_label,
        data=result,
    )
    await audit_log.record(
        session,
        organization_id=org_id,
        action=f"incident.action.{action}",
        actor_type=ActorType.user if actor_id else ActorType.system,
        user_id=actor_id,
        actor_label=actor_label,
        agent_id=incident.agent_id,
        metadata={"incident": incident.key, **result},
    )
    return result
