"""SCIM 2.0 business logic — provisioning, deprovisioning, group→role sync.

The SCIM resources (`scim_users`, `scim_groups`) are the IdP's view; the real
access grant is a `memberships` row that this module creates and removes as the
IdP activates and deactivates the user.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit_log
from ..models import (
    Membership,
    ScimConfig,
    ScimGroup,
    ScimGroupMember,
    ScimUser,
    Session,
    User,
)
from ..models.enums import ActorType, MembershipRole
from ..security import hash_token
from . import roles
from .schemas import PatchOperation, ScimError, ScimGroupIn, ScimUserIn

_FILTER_RE = re.compile(r'^\s*(\w+)\s+eq\s+"([^"]*)"\s*$', re.IGNORECASE)


# --- auth ---------------------------------------------------------------


async def authenticate(session: AsyncSession, token: str | None) -> ScimConfig:
    if not token:
        raise ScimError(401, "missing bearer token")
    cfg = await session.scalar(
        select(ScimConfig).where(
            ScimConfig.token_hash == hash_token(token), ScimConfig.enabled.is_(True)
        )
    )
    if cfg is None:
        raise ScimError(401, "invalid or disabled SCIM token")
    cfg.last_request_at = datetime.now(UTC)
    return cfg


def parse_filter(raw: str | None) -> tuple[str, str] | None:
    if not raw:
        return None
    m = _FILTER_RE.match(raw)
    if not m:
        raise ScimError(400, f"unsupported filter: {raw!r}", scim_type="invalidFilter")
    return m.group(1), m.group(2)


# --- membership sync ---------------------------------------------------


async def _group_roles_for(session: AsyncSession, su: ScimUser) -> list[MembershipRole]:
    rows = (
        await session.scalars(
            select(ScimGroup.mapped_role)
            .join(ScimGroupMember, ScimGroupMember.group_id == ScimGroup.id)
            .where(ScimGroupMember.scim_user_id == su.id, ScimGroup.mapped_role.is_not(None))
        )
    ).all()
    return [r for r in rows if r is not None]


async def sync_membership(session: AsyncSession, cfg: ScimConfig, su: ScimUser) -> None:
    """Reconcile the user's `memberships` row with their SCIM active flag + groups."""
    membership = await session.scalar(
        select(Membership).where(
            Membership.organization_id == cfg.organization_id,
            Membership.user_id == su.user_id,
        )
    )
    # An owner is never SCIM-managed.
    if membership is not None and membership.role == MembershipRole.owner:
        return

    if not su.active:
        if membership is not None:
            await session.delete(membership)
        await _revoke_org_sessions(session, cfg.organization_id, su.user_id)
        return

    role = roles.most_privileged(await _group_roles_for(session, su)) or cfg.default_role
    if membership is None:
        session.add(Membership(organization_id=cfg.organization_id, user_id=su.user_id, role=role))
    elif membership.role != role:
        membership.role = role


async def _revoke_org_sessions(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID
) -> None:
    rows = (
        await session.scalars(
            select(Session).where(
                Session.user_id == user_id,
                Session.organization_id == org_id,
                Session.revoked_at.is_(None),
            )
        )
    ).all()
    for row in rows:
        row.revoked_at = datetime.now(UTC)
        row.revoked_reason = "scim_deprovision"


async def _audit(session: AsyncSession, cfg: ScimConfig, action: str, **meta) -> None:
    await audit_log.record(
        session,
        organization_id=cfg.organization_id,
        action=action,
        actor_type=ActorType.system,
        actor_label="scim",
        metadata=meta,
    )


# --- users -----------------------------------------------------------


async def list_users(
    session: AsyncSession, cfg: ScimConfig, *, filter_: str | None, start: int, count: int
) -> tuple[int, list[ScimUser]]:
    where = [ScimUser.organization_id == cfg.organization_id]
    parsed = parse_filter(filter_)
    if parsed:
        attr, value = parsed
        if attr.lower() == "username":
            where.append(func.lower(ScimUser.user_name) == value.lower())
        elif attr.lower() == "externalid":
            where.append(ScimUser.external_id == value)
        else:
            raise ScimError(400, f"cannot filter on {attr!r}", scim_type="invalidFilter")
    total = await session.scalar(select(func.count()).select_from(ScimUser).where(*where))
    rows = (
        await session.scalars(
            select(ScimUser)
            .where(*where)
            .order_by(ScimUser.created_at)
            .offset(start - 1)
            .limit(count)
        )
    ).all()
    return int(total or 0), list(rows)


async def get_user(session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID) -> ScimUser:
    su = await session.get(ScimUser, scim_id)
    if su is None or su.organization_id != cfg.organization_id:
        raise ScimError(404, "user not found")
    return su


async def load_local_user(session: AsyncSession, su: ScimUser) -> User:
    user = await session.get(User, su.user_id)
    assert user is not None
    return user


async def create_user(session: AsyncSession, cfg: ScimConfig, payload: ScimUserIn) -> ScimUser:
    user_name = (payload.userName or "").strip()
    if not user_name:
        raise ScimError(400, "userName is required", scim_type="invalidValue")
    email = payload.primary_email()
    if not email:
        raise ScimError(
            400, "an email or email-shaped userName is required", scim_type="invalidValue"
        )

    dup = await session.scalar(
        select(ScimUser.id).where(
            ScimUser.organization_id == cfg.organization_id,
            func.lower(ScimUser.user_name) == user_name.lower(),
        )
    )
    if dup:
        raise ScimError(409, "userName already provisioned", scim_type="uniqueness")

    user = await session.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        user = User(email=email, full_name=payload.full_name(), hashed_password=None)
        session.add(user)
        await session.flush()
    elif payload.full_name() and not user.full_name:
        user.full_name = payload.full_name()

    existing = await session.scalar(
        select(ScimUser).where(
            ScimUser.organization_id == cfg.organization_id, ScimUser.user_id == user.id
        )
    )
    if existing is not None:
        raise ScimError(409, "user already provisioned", scim_type="uniqueness")

    su = ScimUser(
        organization_id=cfg.organization_id,
        user_id=user.id,
        external_id=payload.externalId,
        user_name=user_name,
        active=payload.active,
        raw=payload.model_dump(mode="json", exclude_none=True),
    )
    session.add(su)
    await session.flush()
    await sync_membership(session, cfg, su)
    await _audit(session, cfg, "scim.user.create", user_name=user_name, active=su.active)
    return su


async def replace_user(
    session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID, payload: ScimUserIn
) -> ScimUser:
    su = await get_user(session, cfg, scim_id)
    user = await load_local_user(session, su)

    if payload.userName:
        su.user_name = payload.userName.strip()
    if payload.externalId is not None:
        su.external_id = payload.externalId
    if payload.full_name():
        user.full_name = payload.full_name()
    new_email = payload.primary_email()
    if new_email and new_email != user.email:
        clash = await session.scalar(
            select(User.id).where(func.lower(User.email) == new_email, User.id != user.id)
        )
        if clash:
            raise ScimError(409, "email already in use", scim_type="uniqueness")
        user.email = new_email

    was_active = su.active
    su.active = payload.active
    su.raw = payload.model_dump(mode="json", exclude_none=True)
    su.deprovisioned_at = None if su.active else (su.deprovisioned_at or datetime.now(UTC))
    await session.flush()
    await sync_membership(session, cfg, su)
    if was_active != su.active:
        await _audit(
            session,
            cfg,
            "scim.user.deactivate" if not su.active else "scim.user.reactivate",
            user_name=su.user_name,
        )
    return su


def _set_path(payload_raw: dict, path: str, value) -> None:
    if "." in path:
        head, tail = path.split(".", 1)
        payload_raw.setdefault(head, {})[tail] = value
    else:
        payload_raw[path] = value


async def patch_user(
    session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID, ops: list[PatchOperation]
) -> ScimUser:
    su = await get_user(session, cfg, scim_id)
    user = await load_local_user(session, su)
    raw = dict(su.raw or {})
    was_active = su.active

    for op in ops:
        verb = op.op.lower()
        if verb not in {"add", "replace", "remove"}:
            raise ScimError(400, f"unsupported op {op.op!r}", scim_type="invalidSyntax")
        # path-less replace/add: value is a dict of attributes
        if not op.path:
            if not isinstance(op.value, dict):
                raise ScimError(
                    400, "path-less operation needs an object value", scim_type="invalidValue"
                )
            items = op.value.items()
        else:
            items = [(op.path, None if verb == "remove" else op.value)]

        for path, value in items:
            key = path.lower().split("[")[0]
            if key == "active":
                su.active = bool(value) if not isinstance(value, str) else value.lower() == "true"
            elif key == "username":
                su.user_name = str(value).strip()
            elif key == "externalid":
                su.external_id = None if value is None else str(value)
            elif key in {"name.givenname", "name.familyname", "name.formatted"}:
                _set_path(raw, path, value)
                nm = raw.get("name") or {}
                user.full_name = (
                    nm.get("formatted")
                    or " ".join(p for p in (nm.get("givenName"), nm.get("familyName")) if p)
                    or user.full_name
                )
            elif key in {"emails", "emails.value"}:
                new_email = _first_email(value)
                if new_email:
                    user.email = new_email
            elif key in {"displayname", "name"}:
                _set_path(raw, path, value)
            # unknown paths are ignored (SCIM servers may)

    su.raw = raw
    su.deprovisioned_at = None if su.active else (su.deprovisioned_at or datetime.now(UTC))
    await session.flush()
    await sync_membership(session, cfg, su)
    if was_active != su.active:
        await _audit(
            session,
            cfg,
            "scim.user.deactivate" if not su.active else "scim.user.reactivate",
            user_name=su.user_name,
        )
    return su


def _first_email(value) -> str | None:
    if isinstance(value, str) and "@" in value:
        return value.strip().lower()
    if isinstance(value, list) and value:
        first = value[0]
        if isinstance(first, dict) and first.get("value"):
            return str(first["value"]).strip().lower()
    if isinstance(value, dict) and value.get("value"):
        return str(value["value"]).strip().lower()
    return None


async def delete_user(session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID) -> None:
    su = await get_user(session, cfg, scim_id)
    user_name = su.user_name
    su.active = False
    await sync_membership(session, cfg, su)
    await session.execute(delete(ScimGroupMember).where(ScimGroupMember.scim_user_id == su.id))
    await session.delete(su)
    await _audit(session, cfg, "scim.user.delete", user_name=user_name)


# --- groups --------------------------------------------------------


async def list_groups(
    session: AsyncSession, cfg: ScimConfig, *, filter_: str | None, start: int, count: int
) -> tuple[int, list[ScimGroup]]:
    where = [ScimGroup.organization_id == cfg.organization_id]
    parsed = parse_filter(filter_)
    if parsed:
        attr, value = parsed
        if attr.lower() == "displayname":
            where.append(func.lower(ScimGroup.display_name) == value.lower())
        elif attr.lower() == "externalid":
            where.append(ScimGroup.external_id == value)
        else:
            raise ScimError(400, f"cannot filter on {attr!r}", scim_type="invalidFilter")
    total = await session.scalar(select(func.count()).select_from(ScimGroup).where(*where))
    rows = (
        await session.scalars(
            select(ScimGroup)
            .where(*where)
            .order_by(ScimGroup.created_at)
            .offset(start - 1)
            .limit(count)
        )
    ).all()
    return int(total or 0), list(rows)


async def get_group(session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID) -> ScimGroup:
    sg = await session.get(ScimGroup, scim_id)
    if sg is None or sg.organization_id != cfg.organization_id:
        raise ScimError(404, "group not found")
    return sg


async def group_members(session: AsyncSession, sg: ScimGroup) -> list[tuple[str, str]]:
    rows = (
        await session.execute(
            select(ScimUser.id, ScimUser.user_name)
            .join(ScimGroupMember, ScimGroupMember.scim_user_id == ScimUser.id)
            .where(ScimGroupMember.group_id == sg.id)
        )
    ).all()
    return [(str(mid), name) for mid, name in rows]


async def create_group(session: AsyncSession, cfg: ScimConfig, payload: ScimGroupIn) -> ScimGroup:
    name = (payload.displayName or "").strip()
    if not name:
        raise ScimError(400, "displayName is required", scim_type="invalidValue")
    dup = await session.scalar(
        select(ScimGroup.id).where(
            ScimGroup.organization_id == cfg.organization_id,
            func.lower(ScimGroup.display_name) == name.lower(),
        )
    )
    if dup:
        raise ScimError(409, "displayName already exists", scim_type="uniqueness")
    sg = ScimGroup(
        organization_id=cfg.organization_id,
        display_name=name,
        external_id=payload.externalId,
        mapped_role=roles.role_from_display_name(name),
        raw=payload.model_dump(mode="json", exclude_none=True),
    )
    session.add(sg)
    await session.flush()
    await _set_members(session, cfg, sg, [m.value for m in payload.members if m.value])
    await _audit(
        session,
        cfg,
        "scim.group.create",
        display_name=name,
        mapped_role=getattr(sg.mapped_role, "value", None),
    )
    return sg


async def replace_group(
    session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID, payload: ScimGroupIn
) -> ScimGroup:
    sg = await get_group(session, cfg, scim_id)
    if payload.displayName:
        sg.display_name = payload.displayName.strip()
        sg.mapped_role = roles.role_from_display_name(sg.display_name)
    if payload.externalId is not None:
        sg.external_id = payload.externalId
    sg.raw = payload.model_dump(mode="json", exclude_none=True)
    await session.flush()
    await _set_members(session, cfg, sg, [m.value for m in payload.members if m.value])
    return sg


async def patch_group(
    session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID, ops: list[PatchOperation]
) -> ScimGroup:
    sg = await get_group(session, cfg, scim_id)
    current = {mid for mid, _ in await group_members(session, sg)}

    for op in ops:
        verb = op.op.lower()
        path = (op.path or "").lower().split("[")[0]
        if path in {"", "members"} and verb in {"add", "replace"}:
            ids = _member_ids(op.value)
            if verb == "replace" and path == "members":
                current = set(ids)
            else:
                current |= set(ids)
        elif path == "members" and verb == "remove":
            if op.value is None:
                current = set()
            else:
                current -= set(_member_ids(op.value))
        elif path == "displayname" and verb in {"add", "replace"}:
            sg.display_name = str(op.value).strip()
            sg.mapped_role = roles.role_from_display_name(sg.display_name)
        elif path == "externalid":
            sg.external_id = None if verb == "remove" else str(op.value)
        else:
            raise ScimError(
                400, f"unsupported group op {op.op!r} on {op.path!r}", scim_type="invalidPath"
            )

    await _set_members(session, cfg, sg, list(current))
    return sg


def _member_ids(value) -> list[str]:
    if isinstance(value, dict):
        value = [value]
    if isinstance(value, list):
        return [str(v["value"]) for v in value if isinstance(v, dict) and v.get("value")]
    return []


async def _set_members(
    session: AsyncSession, cfg: ScimConfig, sg: ScimGroup, member_ids: list[str]
) -> None:
    wanted: set[uuid.UUID] = set()
    for raw in member_ids:
        try:
            wanted.add(uuid.UUID(str(raw)))
        except ValueError:
            continue
    valid = set(
        (
            await session.scalars(
                select(ScimUser.id).where(
                    ScimUser.organization_id == cfg.organization_id,
                    ScimUser.id.in_(wanted or {uuid.uuid4()}),
                )
            )
        ).all()
    )
    have = set(
        (
            await session.scalars(
                select(ScimGroupMember.scim_user_id).where(ScimGroupMember.group_id == sg.id)
            )
        ).all()
    )
    for gone in have - valid:
        await session.execute(
            delete(ScimGroupMember).where(
                ScimGroupMember.group_id == sg.id, ScimGroupMember.scim_user_id == gone
            )
        )
    for added in valid - have:
        session.add(ScimGroupMember(group_id=sg.id, scim_user_id=added))
    await session.flush()

    # Any user whose group set changed needs its role recomputed.
    for uid in have | valid:
        su = await session.get(ScimUser, uid)
        if su is not None:
            await sync_membership(session, cfg, su)


async def delete_group(session: AsyncSession, cfg: ScimConfig, scim_id: uuid.UUID) -> None:
    sg = await get_group(session, cfg, scim_id)
    display_name = sg.display_name
    members = [mid for mid, _ in await group_members(session, sg)]
    await session.delete(sg)
    await session.flush()
    for raw in members:
        su = await session.get(ScimUser, uuid.UUID(raw))
        if su is not None:
            await sync_membership(session, cfg, su)
    await _audit(session, cfg, "scim.group.delete", display_name=display_name)
