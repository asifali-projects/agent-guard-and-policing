"""SCIM 2.0 provisioning — discovery, user lifecycle, group→role sync, tenancy
(PRD §51)."""

from __future__ import annotations

from .test_auth import bearer, register

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


async def _enable_scim(api, owner_token: str, org: str) -> str:
    put = await api.put(
        f"/v1/organizations/{org}/scim",
        json={"enabled": True, "default_role": "developer"},
        headers=bearer(owner_token),
    )
    assert put.status_code == 200, put.text
    rot = await api.post(f"/v1/organizations/{org}/scim/rotate-token", headers=bearer(owner_token))
    assert rot.status_code == 200, rot.text
    return rot.json()["token"]


def _scim(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


def _user_body(user_name: str, *, active: bool = True) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "userName": user_name,
        "externalId": f"ext-{user_name}",
        "name": {"givenName": "Dana", "familyName": "Scully"},
        "emails": [{"value": user_name, "primary": True, "type": "work"}],
        "active": active,
    }


async def _members(api, owner_token: str, org: str) -> dict[str, dict]:
    resp = await api.get(f"/v1/organizations/{org}/members", headers=bearer(owner_token))
    assert resp.status_code == 200, resp.text
    return {m["email"]: m for m in resp.json()}


# --- discovery + auth ----------------------------------------------------


async def test_discovery_endpoints(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    scim = await _enable_scim(api, tok["access_token"], org)

    spc = await api.get("/scim/v2/ServiceProviderConfig", headers=_scim(scim))
    assert spc.status_code == 200
    assert spc.json()["patch"]["supported"] is True

    rt = await api.get("/scim/v2/ResourceTypes", headers=_scim(scim))
    assert rt.status_code == 200
    assert {r["name"] for r in rt.json()["Resources"]} == {"User", "Group"}

    sch = await api.get("/scim/v2/Schemas", headers=_scim(scim))
    assert sch.status_code == 200


async def test_auth_is_required(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    await _enable_scim(api, tok["access_token"], org)

    anon = await api.get("/scim/v2/Users")
    assert anon.status_code == 401
    assert ERROR_SCHEMA in anon.json()["schemas"]

    bad = await api.get("/scim/v2/Users", headers=_scim("nope-not-a-token"))
    assert bad.status_code == 401


# --- user lifecycle ----------------------------------------------------


async def test_user_provision_deprovision_reactivate(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    owner = tok["access_token"]
    scim = await _enable_scim(api, owner, org)

    created = await api.post(
        "/scim/v2/Users", json=_user_body("dana@corp.example"), headers=_scim(scim)
    )
    assert created.status_code == 201, created.text
    uid = created.json()["id"]
    assert created.headers["location"].endswith(f"/Users/{uid}")
    assert created.json()["active"] is True

    # membership was provisioned at the default role
    assert _members_role(await _members(api, owner, org), "dana@corp.example") == "developer"

    # filter by userName
    listed = await api.get(
        '/scim/v2/Users?filter=userName eq "dana@corp.example"', headers=_scim(scim)
    )
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1

    # PUT active:false -> membership revoked
    off = await api.put(
        f"/scim/v2/Users/{uid}",
        json=_user_body("dana@corp.example", active=False),
        headers=_scim(scim),
    )
    assert off.status_code == 200
    assert off.json()["active"] is False
    assert "dana@corp.example" not in await _members(api, owner, org)

    # PATCH active:true -> membership restored
    on = await api.patch(
        f"/scim/v2/Users/{uid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": True}],
        },
        headers=_scim(scim),
    )
    assert on.status_code == 200
    assert on.json()["active"] is True
    assert "dana@corp.example" in await _members(api, owner, org)

    # DELETE
    gone = await api.delete(f"/scim/v2/Users/{uid}", headers=_scim(scim))
    assert gone.status_code == 204
    assert (await api.get(f"/scim/v2/Users/{uid}", headers=_scim(scim))).status_code == 404
    assert "dana@corp.example" not in await _members(api, owner, org)


async def test_duplicate_user_conflict(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    scim = await _enable_scim(api, tok["access_token"], org)
    body = _user_body("dup@corp.example")
    assert (await api.post("/scim/v2/Users", json=body, headers=_scim(scim))).status_code == 201
    again = await api.post("/scim/v2/Users", json=body, headers=_scim(scim))
    assert again.status_code == 409
    assert again.json()["scimType"] == "uniqueness"


# --- groups -> roles -------------------------------------------------


async def test_group_membership_drives_role(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    owner = tok["access_token"]
    scim = await _enable_scim(api, owner, org)

    u = await api.post("/scim/v2/Users", json=_user_body("gina@corp.example"), headers=_scim(scim))
    uid = u.json()["id"]
    assert _members_role(await _members(api, owner, org), "gina@corp.example") == "developer"

    grp = await api.post(
        "/scim/v2/Groups",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Security Admin",
            "members": [{"value": uid}],
        },
        headers=_scim(scim),
    )
    assert grp.status_code == 201, grp.text
    gid = grp.json()["id"]
    assert grp.json()["agentGuardRole"] == "security_admin"
    assert _members_role(await _members(api, owner, org), "gina@corp.example") == "security_admin"

    # remove the member -> role falls back to the default
    patched = await api.patch(
        f"/scim/v2/Groups/{gid}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "members", "value": [{"value": uid}]}],
        },
        headers=_scim(scim),
    )
    assert patched.status_code == 200
    assert _members_role(await _members(api, owner, org), "gina@corp.example") == "developer"


# --- tenancy --------------------------------------------------------


async def test_scim_token_is_tenant_scoped(api):
    _, _, a = await register(api)
    _, _, b = await register(api)
    scim_a = await _enable_scim(api, a["access_token"], a["organization_id"])
    scim_b = await _enable_scim(api, b["access_token"], b["organization_id"])

    made = await api.post(
        "/scim/v2/Users", json=_user_body("shared@corp.example"), headers=_scim(scim_a)
    )
    uid = made.json()["id"]

    assert (await api.get(f"/scim/v2/Users/{uid}", headers=_scim(scim_a))).status_code == 200
    assert (await api.get(f"/scim/v2/Users/{uid}", headers=_scim(scim_b))).status_code == 404


def _members_role(members: dict[str, dict], email: str) -> str | None:
    row = members.get(email)
    return row["role"] if row else None
