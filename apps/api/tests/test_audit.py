"""Audit read + chain verification (PRD §33)."""

from __future__ import annotations

from .test_auth import bearer, register
from .test_runtime import _bind, _evaluate, _setup


async def test_audit_events_listed_and_chain_intact(api):
    org, h, agent, tool = await _setup(api)
    await _bind(api, h, org, "DENYALL", {"rules": [{"effect": "deny", "actions": ["*"]}]})
    await _evaluate(api, h, agent["id"], "payment.create")  # -> DENY, audited

    page = await api.get("/v1/audit/events", headers=h)
    assert page.status_code == 200
    actions = {e["action"] for e in page.json()["items"]}
    assert "auth.register" in actions
    assert "runtime.evaluate" in actions
    # every event carries a hash-chain link
    assert all(e["entry_hash"] for e in page.json()["items"])

    verify = await api.get("/v1/audit/verify", headers=h)
    assert verify.status_code == 200
    assert verify.json()["intact"] is True
    assert verify.json()["event_count"] >= 2


async def test_audit_filter_and_pagination(api):
    org, h, agent, tool = await _setup(api)
    await _bind(api, h, org, "DENYALL", {"rules": [{"effect": "deny", "actions": ["*"]}]})
    for _ in range(3):
        await _evaluate(api, h, agent["id"], "payment.create")

    filtered = await api.get("/v1/audit/events", params={"decision": "deny", "limit": 2}, headers=h)
    body = filtered.json()
    assert len(body["items"]) == 2
    assert all(e["decision"] == "deny" for e in body["items"])
    assert body["next_cursor"]

    page2 = await api.get(
        "/v1/audit/events",
        params={"decision": "deny", "cursor": body["next_cursor"]},
        headers=h,
    )
    assert page2.status_code == 200


async def test_audit_requires_permission(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]
    dev_email = f"d-{__import__('uuid').uuid4().hex[:8]}@example.com"
    await register(api, email=dev_email)
    await api.post(
        f"/v1/organizations/{org}/members",
        json={"email": dev_email, "role": "developer"},
        headers=bearer(owner["access_token"]),
    )
    dev = await api.post(
        "/v1/auth/login",
        json={
            "email": dev_email,
            "password": "correct horse battery",
            "organization_id": org,
        },
    )
    resp = await api.get("/v1/audit/events", headers=bearer(dev.json()["access_token"]))
    assert resp.status_code == 403  # developer lacks audit.read
