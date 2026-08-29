"""Tenant-facing SCIM configuration — /v1/organizations/{id}/scim (`org.manage`)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..config import get_settings
from ..models import ScimConfig, ScimGroup, ScimUser
from ..models.enums import ActorType, MembershipRole
from ..security import new_opaque_token

router = APIRouter(prefix="/v1/organizations", tags=["scim"])

ManageDep = Annotated[Principal, Depends(require_permission("org.manage"))]


class ScimConfigIn(BaseModel):
    enabled: bool = True
    default_role: str = "developer"


class ScimConfigOut(BaseModel):
    enabled: bool
    default_role: str
    token_set: bool
    last_request_at: str | None
    scim_base_url: str
    users: int
    groups: int


class TokenOut(BaseModel):
    token: str
    scim_base_url: str


def _scoped(principal: Principal, organization_id: uuid.UUID) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")


def _role(value: str) -> MembershipRole:
    try:
        return MembershipRole(value)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role '{value}'"
        ) from exc


def _base() -> str:
    return get_settings().oauth_redirect_base_url.rstrip("/") + "/scim/v2"


async def _load(db: DbSession, organization_id: uuid.UUID) -> ScimConfig | None:
    return await db.scalar(select(ScimConfig).where(ScimConfig.organization_id == organization_id))


async def _out(db: DbSession, cfg: ScimConfig) -> ScimConfigOut:
    users = await db.scalar(
        select(func.count())
        .select_from(ScimUser)
        .where(ScimUser.organization_id == cfg.organization_id)
    )
    groups = await db.scalar(
        select(func.count())
        .select_from(ScimGroup)
        .where(ScimGroup.organization_id == cfg.organization_id)
    )
    return ScimConfigOut(
        enabled=cfg.enabled,
        default_role=cfg.default_role.value,
        token_set=cfg.token_hash is not None,
        last_request_at=cfg.last_request_at.isoformat() if cfg.last_request_at else None,
        scim_base_url=_base(),
        users=int(users or 0),
        groups=int(groups or 0),
    )


@router.get("/{organization_id}/scim", response_model=ScimConfigOut)
async def get_config(
    organization_id: uuid.UUID, db: DbSession, principal: ManageDep
) -> ScimConfigOut:
    _scoped(principal, organization_id)
    cfg = await _load(db, organization_id)
    if cfg is None:
        return ScimConfigOut(
            enabled=False,
            default_role="developer",
            token_set=False,
            last_request_at=None,
            scim_base_url=_base(),
            users=0,
            groups=0,
        )
    return await _out(db, cfg)


@router.put("/{organization_id}/scim", response_model=ScimConfigOut)
async def upsert_config(
    organization_id: uuid.UUID, body: ScimConfigIn, db: DbSession, principal: ManageDep
) -> ScimConfigOut:
    _scoped(principal, organization_id)
    cfg = await _load(db, organization_id)
    if cfg is None:
        cfg = ScimConfig(organization_id=organization_id)
        db.add(cfg)
    cfg.enabled = body.enabled
    cfg.default_role = _role(body.default_role)
    await db.flush()
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="scim.config.update",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"enabled": cfg.enabled, "default_role": cfg.default_role.value},
    )
    return await _out(db, cfg)


@router.post("/{organization_id}/scim/rotate-token", response_model=TokenOut)
async def rotate_token(organization_id: uuid.UUID, db: DbSession, principal: ManageDep) -> TokenOut:
    _scoped(principal, organization_id)
    cfg = await _load(db, organization_id)
    if cfg is None:
        cfg = ScimConfig(organization_id=organization_id)
        db.add(cfg)
    plaintext, token_hash = new_opaque_token(32)
    cfg.token_hash = token_hash
    cfg.enabled = True
    await db.flush()
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="scim.token.rotate",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
    )
    return TokenOut(token=plaintext, scim_base_url=_base())


@router.delete("/{organization_id}/scim/token", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(organization_id: uuid.UUID, db: DbSession, principal: ManageDep) -> None:
    _scoped(principal, organization_id)
    cfg = await _load(db, organization_id)
    if cfg is not None:
        cfg.token_hash = None
        cfg.enabled = False
        await audit_log.record(
            db,
            organization_id=organization_id,
            action="scim.token.revoke",
            actor_type=ActorType.user,
            user_id=principal.user_id,
            actor_label=principal.actor_label,
        )
