"""Internal event bus — canonical events fan out to webhooks + integrations.

PRD §43 (event names), §62 (integrations). Delivery is best-effort and inline:
a slow or failing endpoint never blocks or breaks the request that raised the
event. Kafka-fronted async delivery lands with the worker fleet later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..logging import get_logger
from ..models import Integration, Webhook
from ..models.enums import IntegrationCategory

log = get_logger("events.bus")

# PRD §43
CANONICAL_EVENTS = {
    "agent.action.blocked",
    "agent.action.approval_required",
    "threat.detected",
    "incident.created",
    "incident.updated",
    "policy.violated",
    "redteam.completed",
    "agent.registered",
    "finding.opened",
}

_SECURITY_EVENTS = {"agent.action.blocked", "threat.detected", "policy.violated", "finding.opened"}


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _summary(event_type: str, payload: dict) -> str:
    a = payload.get("agent_name") or payload.get("agent_id") or "an agent"
    kind = payload.get("kind", "threat")
    risk = payload.get("risk_score", "?")
    tool = payload.get("tool", "?")
    if event_type == "threat.detected":
        return f"AgentGuard: {kind} on {a} (risk {risk})"
    if event_type == "incident.created":
        return f"AgentGuard incident {payload.get('key', '')}: {payload.get('title', '')}"
    if event_type == "agent.action.blocked":
        return f"AgentGuard blocked {a} -> {tool} ({payload.get('reason', '')})"
    if event_type == "redteam.completed":
        return f"AgentGuard red-team on {a}: {payload.get('findings', 0)} finding(s)"
    return f"AgentGuard event: {event_type}"


async def _emit_clickhouse(organization_id: uuid.UUID, event_type: str, payload: dict) -> None:
    settings = get_settings()
    url = f"http://{settings.clickhouse_host}:{settings.clickhouse_port}/"
    row = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "organization_id": str(organization_id),
        "agent_id": str(payload.get("agent_id") or uuid.UUID(int=0)),
        "kind": event_type,
        "severity": payload.get("severity", ""),
        "risk_score": int(payload.get("risk_score") or 0),
        "rule_id": payload.get("rule_id", ""),
        "policy_key": payload.get("policy_key", ""),
        "trace_id": "",
        "request_id": payload.get("request_id", ""),
        "detail": json.dumps(payload)[:2000],
    }
    try:
        async with httpx.AsyncClient(timeout=1.5) as c:
            await c.post(
                url,
                params={
                    "query": "INSERT INTO agentguard_events.security_events FORMAT JSONEachRow"
                },
                auth=("agentguard", "agentguard"),
                content=json.dumps(row),
            )
    except Exception as exc:
        log.warning("bus.clickhouse_failed", error=str(exc))


async def _deliver_webhook(client: httpx.AsyncClient, wh: Webhook, envelope: dict) -> None:
    body = json.dumps(envelope).encode()
    headers = {"Content-Type": "application/json", "X-AgentGuard-Event": envelope["type"]}
    if wh.secret_hash:
        headers["X-AgentGuard-Signature"] = sign(wh.secret_hash, body)
    try:
        resp = await client.post(wh.url, content=body, headers=headers)
        wh.last_delivery_at = datetime.now(UTC)
        if resp.status_code >= 400:
            wh.failure_count += 1
    except Exception as exc:
        wh.failure_count += 1
        log.warning("bus.webhook_failed", url=wh.url, error=str(exc))


async def _deliver_integration(
    client: httpx.AsyncClient, integ: Integration, event_type: str, payload: dict, envelope: dict
) -> None:
    cfg = integ.config or {}
    try:
        if integ.provider in {"slack", "teams"} and cfg.get("webhook_url"):
            await client.post(cfg["webhook_url"], json={"text": _summary(event_type, payload)})
        elif integ.provider == "pagerduty" and cfg.get("routing_key"):
            await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json={
                    "routing_key": cfg["routing_key"],
                    "event_action": "trigger",
                    "payload": {
                        "summary": _summary(event_type, payload),
                        "source": "agentguard",
                        "severity": payload.get("severity", "warning") or "warning",
                    },
                },
            )
        elif integ.category == IntegrationCategory.siem and cfg.get("url"):
            await client.post(cfg["url"], json=envelope)
    except Exception as exc:
        integ.status = "error"
        log.warning("bus.integration_failed", provider=integ.provider, error=str(exc))


async def publish(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    envelope = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "organization_id": str(organization_id),
        "created_at": time.time(),
        "data": payload,
    }

    if event_type in _SECURITY_EVENTS:
        await _emit_clickhouse(organization_id, event_type, payload)

    webhooks = (
        await session.scalars(
            select(Webhook).where(
                Webhook.organization_id == organization_id, Webhook.enabled.is_(True)
            )
        )
    ).all()
    integrations = (
        await session.scalars(
            select(Integration).where(
                Integration.organization_id == organization_id,
                Integration.enabled.is_(True),
                Integration.category.in_(
                    [IntegrationCategory.notifications, IntegrationCategory.siem]
                ),
            )
        )
    ).all()

    targets_wh = [w for w in webhooks if not w.events or event_type in w.events]
    if not targets_wh and not integrations:
        return

    async with httpx.AsyncClient(timeout=3.0) as client:
        for wh in targets_wh:
            await _deliver_webhook(client, wh, envelope)
        for integ in integrations:
            await _deliver_integration(client, integ, event_type, payload, envelope)
