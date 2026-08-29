"""Organization + member endpoints — /v1/organizations."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select

from .. import audit_log
from ..auth import service as auth_service
from ..auth.dependencies import (
    CurrentPrincipal,
    CurrentUser,
    DbSession,
    Principal,
    require_permission,
)
from ..models import Membership, Organization, User
from ..models.enums import ActorType, MembershipRole

router = APIRouter(prefix="/v1/organizations", tags=["organizations"])


class OrgOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    region: str
    role: MembershipRole | None = None


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    region: str = Field(default="us", max_length=20)


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    region: str | None = Field(default=None, max_length=20)


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: MembershipRole
    is_active: bool


class MemberAdd(BaseModel):
    email: EmailStr
    role: MembershipRole = MembershipRole.developer


class MemberRoleUpdate(BaseModel):
    role: MembershipRole


@router.get("", response_model=list[OrgOut])
async def my_organizations(user: CurrentUser, db: DbSession) -> list[OrgOut]:
    members = await auth_service.memberships_for(db, user)
    out: list[OrgOut] = []
    for m in members:
        org = await db.get(Organization, m.organization_id)
        if org:
            out.append(
                OrgOut(id=org.id, name=org.name, slug=org.slug, region=org.region, role=m.role)
            )
    return out


@router.post("", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
async def create_organization(body: OrgCreate, user: CurrentUser, db: DbSession) -> OrgOut:
    org = Organization(
        name=body.name.strip(),
        slug=await auth_service.unique_slug(db, body.name),
        region=body.region,
    )
    db.add(org)
    await db.flush()
    db.add(Membership(organization_id=org.id, user_id=user.id, role=MembershipRole.owner))
    await db.flush()
    await audit_log.record(
        db,
        organization_id=org.id,
        action="organization.create",
        actor_type=ActorType.user,
        user_id=user.id,
        actor_label=user.email,
        metadata={"name": org.name},
    )
    return OrgOut(
        id=org.id, name=org.name, slug=org.slug, region=org.region, role=MembershipRole.owner
    )


@router.get("/{organization_id}", response_model=OrgOut)
async def get_organization(
    organization_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("org.read"))],
) -> OrgOut:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")
    org = await db.get(Organization, organization_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return OrgOut(id=org.id, name=org.name, slug=org.slug, region=org.region)


@router.patch("/{organization_id}", response_model=OrgOut)
async def update_organization(
    organization_id: uuid.UUID,
    body: OrgUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("org.manage"))],
) -> OrgOut:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")
    org = await db.get(Organization, organization_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    if body.name is not None:
        org.name = body.name.strip()
    if body.region is not None:
        org.region = body.region
    await audit_log.record(
        db,
        organization_id=org.id,
        action="organization.update",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata=body.model_dump(exclude_none=True),
    )
    return OrgOut(id=org.id, name=org.name, slug=org.slug, region=org.region)


# --- members ---------------------------------------------------------------


async def _scoped(principal: CurrentPrincipal, organization_id: uuid.UUID) -> None:
    if principal.organization_id != organization_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "token is not scoped to this organization")


@router.get("/{organization_id}/members", response_model=list[MemberOut])
async def list_members(
    organization_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("member.read"))],
) -> list[MemberOut]:
    await _scoped(principal, organization_id)
    rows = (
        await db.scalars(select(Membership).where(Membership.organization_id == organization_id))
    ).all()
    out: list[MemberOut] = []
    for m in rows:
        u = await db.get(User, m.user_id)
        if u:
            out.append(
                MemberOut(
                    user_id=u.id,
                    email=u.email,
                    full_name=u.full_name,
                    role=m.role,
                    is_active=u.is_active,
                )
            )
    return out


@router.post(
    "/{organization_id}/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED
)
async def add_member(
    organization_id: uuid.UUID,
    body: MemberAdd,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("member.manage"))],
) -> MemberOut:
    await _scoped(principal, organization_id)
    email = body.email.strip().lower()
    user = await db.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        # Shell account — activated when the person completes sign-up / SSO.
        # A real invitation email is delivered by the notifications worker (Step 9).
        user = User(email=email, is_active=False)
        db.add(user)
        await db.flush()

    existing = await db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == user.id
        )
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already a member")

    db.add(Membership(organization_id=organization_id, user_id=user.id, role=body.role))
    await db.flush()
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="member.add",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"member_email": email, "role": body.role.value},
    )
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=body.role,
        is_active=user.is_active,
    )


@router.patch("/{organization_id}/members/{user_id}", response_model=MemberOut)
async def update_member_role(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    body: MemberRoleUpdate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("member.manage"))],
) -> MemberOut:
    await _scoped(principal, organization_id)
    membership = await db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == user_id
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")

    if membership.role == MembershipRole.owner and body.role != MembershipRole.owner:
        owners = await db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.role == MembershipRole.owner,
            )
        )
        if owners <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot demote the last owner")

    previous = membership.role
    membership.role = body.role
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="member.role_change",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"member_id": str(user_id), "from": previous.value, "to": body.role.value},
    )
    u = await db.get(User, user_id)
    return MemberOut(
        user_id=user_id,
        email=u.email if u else "",
        full_name=u.full_name if u else None,
        role=membership.role,
        is_active=u.is_active if u else False,
    )


@router.delete("/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("member.manage"))],
) -> Response:
    await _scoped(principal, organization_id)
    membership = await db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == user_id
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")
    if membership.role == MembershipRole.owner:
        owners = await db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.role == MembershipRole.owner,
            )
        )
        if owners <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot remove the last owner")

    await db.delete(membership)
    await audit_log.record(
        db,
        organization_id=organization_id,
        action="member.remove",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={"member_id": str(user_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
