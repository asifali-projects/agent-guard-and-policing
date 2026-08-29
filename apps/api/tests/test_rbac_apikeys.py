"""RBAC enforcement + API key system (PRD §50, §52)."""

from __future__ import annotations

import uuid

from .test_auth import bearer, register


async def _add_member(api, owner_token, org_id, email, role):
    resp = await api.post(
        f"/v1/organizations/{org_id}/members",
        json={"email": email, "role": role},
        headers=bearer(owner_token),
    )
    assert resp.status_code == 201, resp.text


async def test_owner_creates_and_uses_api_key(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]

    created = await api.post(
        f"/v1/organizations/{org}/api-keys",
        json={"name": "ci", "scopes": ["apikey.read"], "environment": "development"},
        headers=bearer(owner["access_token"]),
    )
    assert created.status_code == 201, created.text
    full_key = created.json()["key"]
    assert full_key.startswith("ag_dev_")

    # the key itself can now list keys (its scope includes apikey.read)
    listed = await api.get(f"/v1/organizations/{org}/api-keys", headers=bearer(full_key))
    assert listed.status_code == 200
    assert any(k["prefix"] == created.json()["prefix"] for k in listed.json())


async def test_api_key_cannot_exceed_creator_scope(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]
    # owner lacks org.billing (only billing_admin/owner? owner has ALL) -> use a developer
    dev_email = f"dev-{uuid.uuid4().hex[:8]}@example.com"
    await register(api, email=dev_email)
    await _add_member(api, owner["access_token"], org, dev_email, "developer")

    dev_login = await api.post(
        "/v1/auth/login",
        json={"email": dev_email, "password": "correct horse battery", "organization_id": org},
    )
    dev_token = dev_login.json()["access_token"]

    # developer does not hold "member.manage" -> cannot mint a key with it
    resp = await api.post(
        f"/v1/organizations/{org}/api-keys",
        json={"name": "x", "scopes": ["member.manage"]},
        headers=bearer(dev_token),
    )
    assert resp.status_code == 403


async def test_revoked_api_key_is_rejected(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]
    created = await api.post(
        f"/v1/organizations/{org}/api-keys",
        json={"name": "temp", "scopes": ["apikey.read"]},
        headers=bearer(owner["access_token"]),
    )
    key_id = created.json()["id"]
    full_key = created.json()["key"]

    assert (
        await api.get(f"/v1/organizations/{org}/api-keys", headers=bearer(full_key))
    ).status_code == 200

    revoke = await api.delete(
        f"/v1/organizations/{org}/api-keys/{key_id}", headers=bearer(owner["access_token"])
    )
    assert revoke.status_code == 204

    after = await api.get(f"/v1/organizations/{org}/api-keys", headers=bearer(full_key))
    assert after.status_code == 401


async def test_role_permissions_are_enforced(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]

    auditor_email = f"aud-{uuid.uuid4().hex[:8]}@example.com"
    await register(api, email=auditor_email)  # gives them a password + active account
    await _add_member(api, owner["access_token"], org, auditor_email, "auditor")

    login = await api.post(
        "/v1/auth/login",
        json={
            "email": auditor_email,
            "password": "correct horse battery",
            "organization_id": org,
        },
    )
    auditor_token = login.json()["access_token"]

    # auditor may read members ...
    assert (
        await api.get(f"/v1/organizations/{org}/members", headers=bearer(auditor_token))
    ).status_code == 200

    # ... but not add them
    denied = await api.post(
        f"/v1/organizations/{org}/members",
        json={"email": "someone@example.com", "role": "developer"},
        headers=bearer(auditor_token),
    )
    assert denied.status_code == 403


async def test_last_owner_cannot_be_removed(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]
    me = await api.get("/v1/auth/me", headers=bearer(owner["access_token"]))
    my_id = me.json()["id"]

    resp = await api.delete(
        f"/v1/organizations/{org}/members/{my_id}", headers=bearer(owner["access_token"])
    )
    assert resp.status_code == 409


async def test_audit_chain_records_and_verifies(api, _database_url):
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

    from agentguard_api.audit_log import verify_chain
    from agentguard_api.models import AuditEvent, Organization

    _, _, owner = await register(api)
    org_id = uuid.UUID(owner["organization_id"])

    engine = create_async_engine(_database_url)
    async with AsyncSession(engine) as s:
        assert await s.get(Organization, org_id) is not None
        events = (
            await s.scalars(select(AuditEvent).where(AuditEvent.organization_id == org_id))
        ).all()
        assert any(e.action == "auth.register" for e in events)
        assert await verify_chain(s, org_id) is True
    await engine.dispose()
