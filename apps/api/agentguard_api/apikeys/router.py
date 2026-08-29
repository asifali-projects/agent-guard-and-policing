"""API key endpoints — /v1/organizations/{id}/api-keys (PRD §52)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import audit_log
from ..auth.dependencies import CurrentPrincipal, DbSession, Principal, require_permission
from ..models import ApiKey
from ..models.enums import ActorType, ApiKeyType, Environment
from ..rbac.catalog import ALL_PERMISSIONS
from ..security.api_keys import generate_api_key, hash_secret

router = APIRouter(prefix="/v1/organizations/{organization_id}/api-keys", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    key_type: ApiKeyType = ApiKeyType.secret
    environment: Environment = Environment.development
    scopes: list[str] = Field(default_factory=lambda: ["runtime.evaluate"])
    ip_allowlist: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=None, ge=1, le=730)


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    key_type: ApiKeyType
    environment: Environment
    scopes: list[str]
    ip_allowlist: list[str]
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    usage_count: int


class ApiKeyCreated(ApiKeyOut):
    key: str  # full secret, shown exactly once


def _to_out(k: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=k.id,
        name=k.name,
        prefix=k.prefix,
        key_type=k.key_type,
        environment=k.environment,
        scopes=list(k.scopes or []),
        ip_allowlist=list(k.ip_allowlist or []),
        created_at=k.created_at,
        last_used_at=k.last_used_at,
        expires_at=k.expires_at,
        revoked_at=k.revoked_at,
        usage_count=k.usage_count,
    )


async def _scoped(principal: CurrentPrincipal, organization_id: uuid.UUID) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    organization_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("apikey.read"))],
) -> list[ApiKeyOut]:
    await _scoped(principal, organization_id)
    rows = (
        await db.scalars(
            select(ApiKey)
            .where(ApiKey.organization_id == organization_id)
            .order_by(ApiKey.created_at.desc())
        )
    ).all()
    return [_to_out(k) for k in rows]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    organization_id: uuid.UUID,
    body: ApiKeyCreate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("apikey.manage"))],
) -> ApiKeyCreated:
    await _scoped(principal, organization_id)

    unknown = set(body.scopes) - set(ALL_PERMISSIONS)
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown scopes: {sorted(unknown)}"
        )
    # A key can never grant more than its creator holds.
    over = set(body.scopes) - principal.permissions
    if over:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"cannot grant scopes you don't hold: {sorted(over)}"
        )

    full_key, parts = generate_api_key(body.environment)
    expires_at = (
        datetime.now(UTC).replace(microsecond=0) + timedelta(days=body.expires_in_days)
        if body.expires_in_days
        else None
    )
    key = ApiKey(
        organization_id=organization_id,
        name=body.name,
        prefix=parts.prefix,
        hashed_key=hash_secret(parts.secret),
        key_type=body.key_type,
        environment=body.environment,
        scopes=body.scopes,
        ip_allowlist=body.ip_allowlist,
        created_by_id=principal.user_id,
        expires_at=expires_at,
    )
    db.add(key)
    await db.flush()
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="apikey.create",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={
            "prefix": parts.prefix,
            "type": body.key_type.value,
            "env": body.environment.value,
        },
    )
    return ApiKeyCreated(**_to_out(key).model_dump(), key=full_key)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    organization_id: uuid.UUID,
    key_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("apikey.manage"))],
) -> Response:
    await _scoped(principal, organization_id)
    key = await db.get(ApiKey, key_id)
    if key is None or key.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="apikey.revoke",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"prefix": key.prefix},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
