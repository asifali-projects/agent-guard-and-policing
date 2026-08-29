"""Integration + webhook endpoints — /v1/integrations, /v1/webhooks (PRD §62)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..events import bus
from ..models import Integration, Webhook
from ..models.enums import ActorType, IntegrationCategory

router = APIRouter(tags=["integrations"])

ReadDep = Annotated[Principal, Depends(require_permission("integration.read"))]
ManageDep = Annotated[Principal, Depends(require_permission("integration.manage"))]

# PRD §62
CATALOG: dict[str, list[str]] = {
    "identity": ["okta", "microsoft_entra", "auth0"],
    "siem": ["splunk", "microsoft_sentinel", "elastic"],
    "devops": ["github", "gitlab", "bitbucket"],
    "notifications": ["slack", "teams", "pagerduty"],
    "ticketing": ["jira", "servicenow"],
    "cloud": ["aws", "azure", "gcp"],
}
_PROVIDER_CATEGORY = {p: c for c, ps in CATALOG.items() for p in ps}


# --- integrations -------------------------------------------------------


class IntegrationIn(BaseModel):
    provider: str
    config: dict = Field(default_factory=dict)
    enabled: bool = True


class IntegrationPatch(BaseModel):
    config: dict | None = None
    enabled: bool | None = None


class IntegrationOut(BaseModel):
    id: uuid.UUID
    provider: str
    category: IntegrationCategory
    enabled: bool
    status: str
    config: dict
    created_at: datetime


def _int_out(i: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=i.id,
        provider=i.provider,
        category=i.category,
        enabled=i.enabled,
        status=i.status,
        config=i.config,
        created_at=i.created_at,
    )


@router.get("/v1/integrations/catalog")
async def catalog(principal: ReadDep) -> dict:
    return CATALOG


@router.get("/v1/integrations", response_model=list[IntegrationOut])
async def list_integrations(db: DbSession, principal: ReadDep) -> list[IntegrationOut]:
    rows = (
        await db.scalars(
            select(Integration).where(Integration.organization_id == principal.organization_id)
        )
    ).all()
    return [_int_out(i) for i in rows]


@router.post("/v1/integrations", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED)
async def create_integration(
    body: IntegrationIn, db: DbSession, principal: ManageDep
) -> IntegrationOut:
    if body.provider not in _PROVIDER_CATEGORY:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown provider '{body.provider}'"
        )
    dup = await db.scalar(
        select(Integration.id).where(
            Integration.organization_id == principal.organization_id,
            Integration.provider == body.provider,
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "integration already configured")
    integ = Integration(
        organization_id=principal.organization_id,
        provider=body.provider,
        category=IntegrationCategory(_PROVIDER_CATEGORY[body.provider]),
        enabled=body.enabled,
        status="connected",
        config=body.config,
        created_by_id=principal.user_id,
    )
    db.add(integ)
    await db.flush()
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="integration.connect",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"provider": body.provider},
    )
    return _int_out(integ)


async def _load_int(db, principal: Principal, iid: uuid.UUID) -> Integration:
    i = await db.get(Integration, iid)
    if i is None or i.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    return i


@router.patch("/v1/integrations/{integration_id}", response_model=IntegrationOut)
async def update_integration(
    integration_id: uuid.UUID, body: IntegrationPatch, db: DbSession, principal: ManageDep
) -> IntegrationOut:
    i = await _load_int(db, principal, integration_id)
    if body.config is not None:
        i.config = body.config
    if body.enabled is not None:
        i.enabled = body.enabled
    await db.flush()
    return _int_out(i)


@router.delete("/v1/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: uuid.UUID, db: DbSession, principal: ManageDep
) -> Response:
    i = await _load_int(db, principal, integration_id)
    await db.delete(i)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- webhooks -------------------------------------------------------


class WebhookIn(BaseModel):
    url: str = Field(min_length=8, max_length=500)
    events: list[str] = Field(default_factory=list)
    secret: str | None = None
    enabled: bool = True


class WebhookPatch(BaseModel):
    url: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None


class WebhookOut(BaseModel):
    id: uuid.UUID
    url: str
    events: list[str]
    enabled: bool
    last_delivery_at: datetime | None
    failure_count: int
    created_at: datetime


def _wh_out(w: Webhook) -> WebhookOut:
    return WebhookOut(
        id=w.id,
        url=w.url,
        events=list(w.events or []),
        enabled=w.enabled,
        last_delivery_at=w.last_delivery_at,
        failure_count=w.failure_count,
        created_at=w.created_at,
    )


@router.get("/v1/webhooks", response_model=list[WebhookOut])
async def list_webhooks(db: DbSession, principal: ReadDep) -> list[WebhookOut]:
    rows = (
        await db.scalars(
            select(Webhook).where(Webhook.organization_id == principal.organization_id)
        )
    ).all()
    return [_wh_out(w) for w in rows]


@router.post("/v1/webhooks", response_model=WebhookOut, status_code=status.HTTP_201_CREATED)
async def create_webhook(body: WebhookIn, db: DbSession, principal: ManageDep) -> WebhookOut:
    unknown = set(body.events) - bus.CANONICAL_EVENTS
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown events: {sorted(unknown)} (valid: {sorted(bus.CANONICAL_EVENTS)})",
        )
    wh = Webhook(
        organization_id=principal.organization_id,
        url=body.url,
        events=body.events,
        secret_hash=body.secret,  # stored as the signing key; never returned
        enabled=body.enabled,
    )
    db.add(wh)
    await db.flush()
    return _wh_out(wh)


async def _load_wh(db, principal: Principal, wid: uuid.UUID) -> Webhook:
    w = await db.get(Webhook, wid)
    if w is None or w.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "webhook not found")
    return w


@router.patch("/v1/webhooks/{webhook_id}", response_model=WebhookOut)
async def update_webhook(
    webhook_id: uuid.UUID, body: WebhookPatch, db: DbSession, principal: ManageDep
) -> WebhookOut:
    w = await _load_wh(db, principal, webhook_id)
    for f, v in body.model_dump(exclude_none=True).items():
        setattr(w, f, v)
    await db.flush()
    return _wh_out(w)


@router.delete("/v1/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(webhook_id: uuid.UUID, db: DbSession, principal: ManageDep) -> Response:
    w = await _load_wh(db, principal, webhook_id)
    await db.delete(w)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/v1/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: uuid.UUID, db: DbSession, principal: ManageDep) -> dict:
    w = await _load_wh(db, principal, webhook_id)
    envelope = {"id": str(uuid.uuid4()), "type": "webhook.test", "data": {"ok": True}}
    body = json.dumps(envelope).encode()
    headers = {"Content-Type": "application/json", "X-AgentGuard-Event": "webhook.test"}
    if w.secret_hash:
        headers["X-AgentGuard-Signature"] = bus.sign(w.secret_hash, body)
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            resp = await c.post(w.url, content=body, headers=headers)
        w.last_delivery_at = datetime.now(UTC)
        return {"status_code": resp.status_code}
    except httpx.HTTPError as exc:
        w.failure_count += 1
        return {"error": str(exc)}
