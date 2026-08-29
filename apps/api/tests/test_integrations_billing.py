"""Integrations + webhooks + event bus + billing + usage (PRD §43, §62, §64–65)."""

from __future__ import annotations

from agentguard_api.events import bus

from .test_auth import bearer, register
from .test_runtime import _bind, _evaluate, _setup


async def test_webhook_and_integration_crud(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])

    wh = await api.post(
        "/v1/webhooks",
        json={"url": "https://example.com/hook", "events": ["threat.detected"], "secret": "s3cr3t"},
        headers=h,
    )
    assert wh.status_code == 201
    assert "secret" not in wh.json()  # never returned

    bad = await api.post(
        "/v1/webhooks",
        json={"url": "https://x.example/h", "events": ["not.a.real.event"]},
        headers=h,
    )
    assert bad.status_code == 422

    integ = await api.post(
        "/v1/integrations",
        json={"provider": "slack", "config": {"webhook_url": "https://hooks.slack.com/x"}},
        headers=h,
    )
    assert integ.status_code == 201
    assert integ.json()["category"] == "notifications"

    unknown = await api.post("/v1/integrations", json={"provider": "myspace"}, headers=h)
    assert unknown.status_code == 422

    listed = await api.get("/v1/integrations", headers=h)
    assert len(listed.json()) == 1
    cat = await api.get("/v1/integrations/catalog", headers=h)
    assert "slack" in cat.json()["notifications"]


async def test_event_bus_fans_out_on_block(api, monkeypatch):
    delivered: list[tuple[str, str]] = []

    async def _rec_wh(client, wh, envelope):
        delivered.append(("wh", envelope["type"]))

    async def _rec_int(client, integ, event_type, payload, envelope):
        delivered.append((integ.provider, event_type))

    async def _noop_emit(*a, **k):
        return None

    monkeypatch.setattr(bus, "_deliver_webhook", _rec_wh)
    monkeypatch.setattr(bus, "_deliver_integration", _rec_int)
    monkeypatch.setattr(bus, "_emit_clickhouse", _noop_emit)

    org, h, agent, tool = await _setup(api)
    await api.post(
        "/v1/webhooks",
        json={"url": "https://example.com/hook", "events": ["agent.action.blocked"]},
        headers=h,
    )
    await api.post(
        "/v1/integrations",
        json={"provider": "slack", "config": {"webhook_url": "https://hooks.slack.com/x"}},
        headers=h,
    )
    await _bind(api, h, org, "DENYALL", {"rules": [{"effect": "deny", "actions": ["*"]}]})

    res = await _evaluate(api, h, agent["id"], "payment.create")
    assert res["decision"] == "DENY"
    assert ("wh", "agent.action.blocked") in delivered
    assert ("slack", "agent.action.blocked") in delivered


def test_webhook_signature_is_hmac():
    sig = bus.sign("k", b"hello")
    assert sig.startswith("sha256=") and len(sig) == 71
    assert "redteam.completed" in bus.CANONICAL_EVENTS


async def test_billing_plans_subscription_and_usage(api):
    org, h, agent, tool = await _setup(api)
    # a couple of metered actions
    for _ in range(3):
        await _evaluate(api, h, agent["id"], "invoice.read")

    plans = await api.get("/v1/billing/plans", headers=h)
    assert {p["code"] for p in plans.json()} == {"community", "developer", "team", "business"}

    sub = await api.get("/v1/billing/subscription", headers=h)
    body = sub.json()
    assert body["plan"]["code"] == "community"
    assert body["usage"]["metrics"]["runtime_actions"] >= 3
    assert body["usage"]["metrics"]["agents"] == 1
    assert body["usage"]["limits"]["agents"] == 3

    changed = await api.post("/v1/billing/subscription", json={"plan_code": "team"}, headers=h)
    assert changed.status_code == 200
    assert changed.json()["plan"]["code"] == "team"
    assert changed.json()["usage"]["limits"]["agents"] == 50

    ent = await api.post("/v1/billing/subscription", json={"plan_code": "enterprise"}, headers=h)
    assert ent.status_code == 422


async def test_billing_change_plan_needs_permission(api):
    _, _, owner = await register(api)
    org = owner["organization_id"]
    dev = f"d-{__import__('uuid').uuid4().hex[:8]}@example.com"
    await register(api, email=dev)
    await api.post(
        f"/v1/organizations/{org}/members",
        json={"email": dev, "role": "developer"},
        headers=bearer(owner["access_token"]),
    )
    tok = (
        await api.post(
            "/v1/auth/login",
            json={"email": dev, "password": "correct horse battery", "organization_id": org},
        )
    ).json()["access_token"]
    resp = await api.post(
        "/v1/billing/subscription", json={"plan_code": "team"}, headers=bearer(tok)
    )
    assert resp.status_code == 403  # developer lacks org.billing
