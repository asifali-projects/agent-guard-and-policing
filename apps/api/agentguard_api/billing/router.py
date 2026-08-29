"""Billing endpoints — /v1/billing (PRD §64–65)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import Agent, McpServer, Membership, Plan, Subscription
from ..models.enums import PlanCode, SubscriptionStatus
from . import usage

router = APIRouter(prefix="/v1/billing", tags=["billing"])

ReadDep = Annotated[Principal, Depends(require_permission("org.read"))]
ManageDep = Annotated[Principal, Depends(require_permission("org.billing"))]


class PlanOut(BaseModel):
    code: PlanCode
    name: str
    monthly_price_cents: int
    currency: str
    limits: dict
    is_public: bool


class UsageOut(BaseModel):
    period: str
    metrics: dict[str, int]
    limits: dict
    over_limit: list[str]


class SubscriptionOut(BaseModel):
    plan: PlanOut
    status: SubscriptionStatus
    current_period_start: datetime | None
    current_period_end: datetime | None
    usage: UsageOut


class ChangePlanIn(BaseModel):
    plan_code: PlanCode


def _plan_out(p: Plan) -> PlanOut:
    return PlanOut(
        code=p.code,
        name=p.name,
        monthly_price_cents=p.monthly_price_cents,
        currency=p.currency,
        limits=p.limits or {},
        is_public=p.is_public,
    )


async def _plan(db, code: PlanCode) -> Plan:
    p = await db.scalar(select(Plan).where(Plan.code == code))
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "plan not found")
    return p


@router.get("/plans", response_model=list[PlanOut])
async def list_plans(db: DbSession, principal: ReadDep) -> list[PlanOut]:
    rows = (
        await db.scalars(
            select(Plan).where(Plan.is_public.is_(True)).order_by(Plan.monthly_price_cents)
        )
    ).all()
    return [_plan_out(p) for p in rows]


async def _usage(db, org_id: uuid.UUID, plan: Plan) -> UsageOut:
    from datetime import UTC

    metrics = await usage.current(org_id)
    metrics["agents"] = (
        await db.scalar(
            select(func.count()).select_from(Agent).where(Agent.organization_id == org_id)
        )
        or 0
    )
    metrics["mcp_servers"] = (
        await db.scalar(
            select(func.count()).select_from(McpServer).where(McpServer.organization_id == org_id)
        )
        or 0
    )
    metrics["users"] = (
        await db.scalar(
            select(func.count()).select_from(Membership).where(Membership.organization_id == org_id)
        )
        or 0
    )

    limits = plan.limits or {}
    over = [m for m, lim in limits.items() if isinstance(lim, int) and metrics.get(m, 0) > lim]
    return UsageOut(
        period=datetime.now(UTC).strftime("%Y-%m"), metrics=metrics, limits=limits, over_limit=over
    )


@router.get("/subscription", response_model=SubscriptionOut)
async def get_subscription(db: DbSession, principal: ReadDep) -> SubscriptionOut:
    org_id = principal.organization_id
    sub = await db.scalar(select(Subscription).where(Subscription.organization_id == org_id))
    if sub is None:
        plan = await _plan(db, PlanCode.community)
        return SubscriptionOut(
            plan=_plan_out(plan),
            status=SubscriptionStatus.active,
            current_period_start=None,
            current_period_end=None,
            usage=await _usage(db, org_id, plan),
        )
    plan = await db.get(Plan, sub.plan_id)
    return SubscriptionOut(
        plan=_plan_out(plan),
        status=sub.status,
        current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end,
        usage=await _usage(db, org_id, plan),
    )


@router.post("/subscription", response_model=SubscriptionOut)
async def change_plan(body: ChangePlanIn, db: DbSession, principal: ManageDep) -> SubscriptionOut:
    org_id = principal.organization_id
    plan = await _plan(db, body.plan_code)
    if body.plan_code == PlanCode.enterprise:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Enterprise plans are arranged with sales"
        )
    sub = await db.scalar(select(Subscription).where(Subscription.organization_id == org_id))
    if sub is None:
        sub = Subscription(
            organization_id=org_id, plan_id=plan.id, status=SubscriptionStatus.active
        )
        db.add(sub)
    else:
        sub.plan_id = plan.id
        sub.status = SubscriptionStatus.active
    await db.flush()
    # Stripe / payment-processor wiring (PRD §65) is intentionally out of scope here.
    return SubscriptionOut(
        plan=_plan_out(plan),
        status=sub.status,
        current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end,
        usage=await _usage(db, org_id, plan),
    )
