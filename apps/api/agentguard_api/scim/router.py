"""SCIM 2.0 endpoints — /scim/v2/* (RFC 7644, PRD §51).

Authentication is a per-organization bearer token (not a user JWT or API key);
every route resolves it to a `ScimConfig`. Errors use the SCIM error schema via
the app-level handler for `ScimError`.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..auth.dependencies import DbSession
from ..config import get_settings
from ..models import Membership, ScimConfig
from . import schemas, service
from .schemas import (
    MEDIA_TYPE,
    PatchRequest,
    ScimError,
    ScimGroupIn,
    ScimUserIn,
)

router = APIRouter(prefix="/scim/v2", tags=["scim"])


def _base() -> str:
    return get_settings().oauth_redirect_base_url.rstrip("/")


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token else None


async def _require_scim(
    db: DbSession, authorization: Annotated[str | None, Header()] = None
) -> ScimConfig:
    return await service.authenticate(db, _bearer(authorization))


ScimAuth = Annotated[ScimConfig, Depends(_require_scim)]


def _scim_json(
    content: dict | list, *, status: int = 200, location: str | None = None
) -> JSONResponse:
    headers = {"Location": location} if location else None
    return JSONResponse(content=content, status_code=status, media_type=MEDIA_TYPE, headers=headers)


def _page(start_index: int | None, count: int | None) -> tuple[int, int]:
    start = max(1, start_index or 1)
    n = 100 if count is None else max(0, min(count, 200))
    return start, n


async def _user_out(db, cfg: ScimConfig, su) -> dict:
    # `updated_at` is expired after a flush that ran a server-side onupdate.
    await db.refresh(su)
    user = await service.load_local_user(db, su)
    role = await db.scalar(
        select(Membership.role).where(
            Membership.organization_id == cfg.organization_id, Membership.user_id == su.user_id
        )
    )
    return schemas.user_resource(su, user, base_url=_base(), roles=[role.value] if role else [])


async def _group_out(db, cfg: ScimConfig, sg) -> dict:
    await db.refresh(sg)
    members = await service.group_members(db, sg)
    return schemas.group_resource(sg, members, base_url=_base())


# --- discovery -------------------------------------------------------


@router.get("/ServiceProviderConfig")
async def service_provider_config(_: ScimAuth) -> JSONResponse:
    return _scim_json(schemas.service_provider_config(_base()))


@router.get("/ResourceTypes")
async def resource_types(_: ScimAuth) -> JSONResponse:
    return _scim_json(schemas.resource_types(_base()))


@router.get("/Schemas")
async def list_schemas(_: ScimAuth) -> JSONResponse:
    items = [
        {"id": schemas.USER_SCHEMA, "name": "User", "description": "SCIM core User"},
        {"id": schemas.GROUP_SCHEMA, "name": "Group", "description": "SCIM core Group"},
    ]
    return _scim_json(
        schemas.list_response(items, total=len(items), start_index=1, count=len(items))
    )


# --- users ----------------------------------------------------------


@router.get("/Users")
async def list_users(
    cfg: ScimAuth,
    db: DbSession,
    filter: str | None = None,
    startIndex: int | None = None,
    count: int | None = None,
) -> JSONResponse:
    start, n = _page(startIndex, count)
    total, rows = await service.list_users(db, cfg, filter_=filter, start=start, count=n)
    resources = [await _user_out(db, cfg, su) for su in rows]
    return _scim_json(schemas.list_response(resources, total=total, start_index=start, count=n))


@router.post("/Users")
async def create_user(cfg: ScimAuth, db: DbSession, body: ScimUserIn) -> JSONResponse:
    su = await service.create_user(db, cfg, body)
    out = await _user_out(db, cfg, su)
    return _scim_json(out, status=201, location=out["meta"]["location"])


@router.get("/Users/{scim_id}")
async def get_user(cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID) -> JSONResponse:
    su = await service.get_user(db, cfg, scim_id)
    return _scim_json(await _user_out(db, cfg, su))


@router.put("/Users/{scim_id}")
async def replace_user(
    cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID, body: ScimUserIn
) -> JSONResponse:
    su = await service.replace_user(db, cfg, scim_id, body)
    return _scim_json(await _user_out(db, cfg, su))


@router.patch("/Users/{scim_id}")
async def patch_user(
    cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID, body: PatchRequest
) -> JSONResponse:
    su = await service.patch_user(db, cfg, scim_id, body.Operations)
    return _scim_json(await _user_out(db, cfg, su))


@router.delete("/Users/{scim_id}", status_code=204)
async def delete_user(cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID) -> Response:
    await service.delete_user(db, cfg, scim_id)
    return Response(status_code=204)


# --- groups -------------------------------------------------------


@router.get("/Groups")
async def list_groups(
    cfg: ScimAuth,
    db: DbSession,
    filter: str | None = None,
    startIndex: int | None = None,
    count: int | None = None,
) -> JSONResponse:
    start, n = _page(startIndex, count)
    total, rows = await service.list_groups(db, cfg, filter_=filter, start=start, count=n)
    resources = [await _group_out(db, cfg, sg) for sg in rows]
    return _scim_json(schemas.list_response(resources, total=total, start_index=start, count=n))


@router.post("/Groups")
async def create_group(cfg: ScimAuth, db: DbSession, body: ScimGroupIn) -> JSONResponse:
    sg = await service.create_group(db, cfg, body)
    out = await _group_out(db, cfg, sg)
    return _scim_json(out, status=201, location=out["meta"]["location"])


@router.get("/Groups/{scim_id}")
async def get_group(cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID) -> JSONResponse:
    sg = await service.get_group(db, cfg, scim_id)
    return _scim_json(await _group_out(db, cfg, sg))


@router.put("/Groups/{scim_id}")
async def replace_group(
    cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID, body: ScimGroupIn
) -> JSONResponse:
    sg = await service.replace_group(db, cfg, scim_id, body)
    return _scim_json(await _group_out(db, cfg, sg))


@router.patch("/Groups/{scim_id}")
async def patch_group(
    cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID, body: PatchRequest
) -> JSONResponse:
    sg = await service.patch_group(db, cfg, scim_id, body.Operations)
    return _scim_json(await _group_out(db, cfg, sg))


@router.delete("/Groups/{scim_id}", status_code=204)
async def delete_group(cfg: ScimAuth, db: DbSession, scim_id: uuid.UUID) -> Response:
    await service.delete_group(db, cfg, scim_id)
    return Response(status_code=204)


def scim_error_handler(_: Request, exc: ScimError) -> JSONResponse:
    return _scim_json(
        schemas.error_body(exc.status_code, exc.detail, exc.scim_type), status=exc.status_code
    )
