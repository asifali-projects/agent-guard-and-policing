"""SCIM 2.0 wire types (RFC 7643 / 7644) — just the slice IdPs actually use."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SPC_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

MEDIA_TYPE = "application/scim+json"


class _Loose(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Name(_Loose):
    givenName: str | None = None
    familyName: str | None = None
    formatted: str | None = None


class Email(_Loose):
    value: str | None = None
    primary: bool | None = None
    type: str | None = None


class ScimUserIn(_Loose):
    userName: str | None = None
    externalId: str | None = None
    active: bool = True
    name: Name | None = None
    emails: list[Email] = Field(default_factory=list)
    displayName: str | None = None

    def primary_email(self) -> str | None:
        if self.emails:
            primary = next((e for e in self.emails if e.primary), self.emails[0])
            if primary.value:
                return primary.value.strip().lower()
        if self.userName and "@" in self.userName:
            return self.userName.strip().lower()
        return None

    def full_name(self) -> str | None:
        if self.name and self.name.formatted:
            return self.name.formatted
        if self.name and (self.name.givenName or self.name.familyName):
            return " ".join(p for p in (self.name.givenName, self.name.familyName) if p)
        return self.displayName


class MemberRef(_Loose):
    value: str | None = None  # SCIM id of the member
    display: str | None = None


class ScimGroupIn(_Loose):
    displayName: str | None = None
    externalId: str | None = None
    members: list[MemberRef] = Field(default_factory=list)


class PatchOperation(_Loose):
    op: str
    path: str | None = None
    value: Any = None


class PatchRequest(_Loose):
    Operations: list[PatchOperation] = Field(default_factory=list)


class ScimError(Exception):
    """Raised inside SCIM handlers; the router renders the RFC 7644 error body."""

    def __init__(self, status_code: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type


def error_body(status_code: int, detail: str, scim_type: str | None = None) -> dict:
    body: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(status_code), "detail": detail}
    if scim_type:
        body["scimType"] = scim_type
    return body


def _meta(resource_type: str, location: str, created: datetime, modified: datetime) -> dict:
    return {
        "resourceType": resource_type,
        "created": created.isoformat(),
        "lastModified": modified.isoformat(),
        "location": location,
    }


def user_resource(su, user, *, base_url: str, roles: list[str]) -> dict:
    loc = f"{base_url}/scim/v2/Users/{su.id}"
    given, family = "", ""
    raw_name = (su.raw or {}).get("name") or {}
    if isinstance(raw_name, dict):
        given, family = raw_name.get("givenName") or "", raw_name.get("familyName") or ""
    body = {
        "schemas": [USER_SCHEMA],
        "id": str(su.id),
        "userName": su.user_name,
        "active": su.active,
        "name": {
            "givenName": given,
            "familyName": family,
            "formatted": user.full_name or su.user_name,
        },
        "emails": [{"value": user.email, "primary": True, "type": "work"}],
        "meta": _meta("User", loc, su.created_at, su.updated_at),
    }
    if su.external_id:
        body["externalId"] = su.external_id
    if roles:
        body["roles"] = [{"value": r} for r in roles]
    return body


def group_resource(sg, members: list[tuple[str, str]], *, base_url: str) -> dict:
    loc = f"{base_url}/scim/v2/Groups/{sg.id}"
    body = {
        "schemas": [GROUP_SCHEMA],
        "id": str(sg.id),
        "displayName": sg.display_name,
        "members": [{"value": mid, "display": mdisp} for mid, mdisp in members],
        "meta": _meta("Group", loc, sg.created_at, sg.updated_at),
    }
    if sg.external_id:
        body["externalId"] = sg.external_id
    if sg.mapped_role is not None:
        body["agentGuardRole"] = sg.mapped_role.value
    return body


def list_response(resources: list[dict], *, total: int, start_index: int, count: int) -> dict:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources) if count else 0,
        "Resources": resources if count else [],
    }


def service_provider_config(base_url: str) -> dict:
    return {
        "schemas": [SPC_SCHEMA],
        "documentationUri": f"{base_url}/docs",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication via the SCIM bearer token issued in AgentGuard.",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{base_url}/scim/v2/ServiceProviderConfig",
        },
    }


def resource_types(base_url: str) -> dict:
    def rt(name: str, schema: str) -> dict:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": name,
            "name": name,
            "endpoint": f"/{name}s",
            "schema": schema,
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{base_url}/scim/v2/ResourceTypes/{name}",
            },
        }

    items = [rt("User", USER_SCHEMA), rt("Group", GROUP_SCHEMA)]
    return list_response(items, total=len(items), start_index=1, count=len(items))
