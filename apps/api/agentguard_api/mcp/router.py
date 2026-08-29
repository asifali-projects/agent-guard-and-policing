"""MCP endpoints — /v1/mcp (PRD §17)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .. import audit_log
from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import McpServer
from ..models.enums import ActorType, McpServerStatus, RiskSeverity
from .scanner import scan

router = APIRouter(prefix="/v1/mcp", tags=["mcp"])

ReadDep = Annotated[Principal, Depends(require_permission("mcp.read"))]
ManageDep = Annotated[Principal, Depends(require_permission("mcp.manage"))]


class McpServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    url: str | None = None
    owner_team: str | None = None
    version: str | None = None
    trusted: bool = False
    permissions: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    metadata_flags: dict = Field(default_factory=dict)


class McpServerPatch(BaseModel):
    url: str | None = None
    owner_team: str | None = None
    version: str | None = None
    trusted: bool | None = None
    permissions: list[str] | None = None
    external_dependencies: list[str] | None = None
    metadata_flags: dict | None = None


class McpServerOut(BaseModel):
    id: uuid.UUID
    name: str
    url: str | None
    owner_team: str | None
    version: str | None
    status: McpServerStatus
    risk: RiskSeverity
    trusted: bool
    permissions: list[str]
    external_dependencies: list[str]
    last_scan_at: datetime | None
    scan_summary: dict


class ScanOut(BaseModel):
    server_id: uuid.UUID
    issues: list[str]
    checks: dict
    severity: str
    status: str


async def _load(db, principal: Principal, sid: uuid.UUID) -> McpServer:
    s = await db.get(McpServer, sid)
    if s is None or s.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "MCP server not found")
    return s


@router.get("/servers", response_model=list[McpServerOut])
async def list_servers(db: DbSession, principal: ReadDep) -> list[McpServerOut]:
    rows = (
        await db.scalars(
            select(McpServer)
            .where(McpServer.organization_id == principal.organization_id)
            .order_by(McpServer.name)
        )
    ).all()
    return [_server_out(s) for s in rows]


@router.post("/servers", response_model=McpServerOut, status_code=status.HTTP_201_CREATED)
async def create_server(body: McpServerIn, db: DbSession, principal: ManageDep) -> McpServerOut:
    dup = await db.scalar(
        select(McpServer.id).where(
            McpServer.organization_id == principal.organization_id, McpServer.name == body.name
        )
    )
    if dup:
        raise HTTPException(status.HTTP_409_CONFLICT, "MCP server already registered")
    s = McpServer(
        organization_id=principal.organization_id,
        name=body.name,
        url=body.url,
        owner_team=body.owner_team,
        version=body.version,
        trusted=body.trusted,
        external_dependencies=body.external_dependencies,
        scan_summary={"permissions": body.permissions, "metadata_flags": body.metadata_flags},
    )
    db.add(s)
    await db.flush()
    return _server_out(s)


@router.get("/servers/{server_id}", response_model=McpServerOut)
async def get_server(server_id: uuid.UUID, db: DbSession, principal: ReadDep) -> McpServerOut:
    return _server_out(await _load(db, principal, server_id))


@router.patch("/servers/{server_id}", response_model=McpServerOut)
async def update_server(
    server_id: uuid.UUID, body: McpServerPatch, db: DbSession, principal: ManageDep
) -> McpServerOut:
    s = await _load(db, principal, server_id)
    data = body.model_dump(exclude_none=True)
    summary = dict(s.scan_summary or {})
    if "permissions" in data:
        summary["permissions"] = data.pop("permissions")
    if "metadata_flags" in data:
        summary["metadata_flags"] = data.pop("metadata_flags")
    if "external_dependencies" in data:
        s.external_dependencies = data.pop("external_dependencies")
    for f, v in data.items():
        setattr(s, f, v)
    s.scan_summary = summary
    await db.flush()
    return _server_out(s)


@router.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_server(server_id: uuid.UUID, db: DbSession, principal: ManageDep) -> Response:
    s = await _load(db, principal, server_id)
    await db.delete(s)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/servers/{server_id}/scan", response_model=ScanOut)
async def scan_server(server_id: uuid.UUID, db: DbSession, principal: ManageDep) -> ScanOut:
    s = await _load(db, principal, server_id)
    summary = dict(s.scan_summary or {})
    result = scan(
        trusted=s.trusted,
        url=s.url,
        version=s.version,
        permissions=summary.get("permissions", []),
        external_dependencies=list(s.external_dependencies or []),
        metadata_flags=summary.get("metadata_flags", {}),
    )
    s.risk = RiskSeverity(result["severity"])
    s.status = McpServerStatus(result["status"])
    s.last_scan_at = datetime.now(UTC)
    s.scan_summary = {**summary, "last_result": result}
    await audit_log.record(
        db,
        organization_id=principal.organization_id,
        action="mcp.scan",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"server": s.name, "severity": result["severity"], "issues": result["issues"]},
    )
    return ScanOut(server_id=s.id, **result)


def _server_out(s: McpServer) -> McpServerOut:
    summary = s.scan_summary or {}
    return McpServerOut(
        id=s.id,
        name=s.name,
        url=s.url,
        owner_team=s.owner_team,
        version=s.version,
        status=s.status,
        risk=s.risk,
        trusted=s.trusted,
        permissions=list(summary.get("permissions", [])),
        external_dependencies=list(s.external_dependencies or []),
        last_scan_at=s.last_scan_at,
        scan_summary=summary,
    )
