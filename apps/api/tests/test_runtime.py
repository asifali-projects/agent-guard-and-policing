"""Runtime API + policy engine integration (PRD §23–25, §42)."""

from __future__ import annotations

from .test_auth import bearer, register


async def _setup(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    org = owner["organization_id"]

    agent = await api.post(
        "/v1/agents",
        json={"name": "FinanceAgent", "framework": "langgraph", "environment": "production"},
        headers=h,
    )
    assert agent.status_code == 201, agent.text
    tool = await api.post(
        "/v1/tools",
        json={"name": "payment.create", "risk": "critical"},
        headers=h,
    )
    assert tool.status_code == 201, tool.text
    return org, h, agent.json(), tool.json()


async def _bind(api, h, org, key, spec, *, scope="organization", agent_id=None):
    p = await api.post(
        "/v1/policies",
        json={"key": key, "name": key, "spec": spec},
        headers=h,
    )
    assert p.status_code == 201, p.text
    body = {"scope_type": scope}
    if agent_id:
        body["agent_id"] = agent_id
    b = await api.post(f"/v1/policies/{p.json()['id']}/bindings", json=body, headers=h)
    assert b.status_code == 201, b.text
    return p.json()


async def _evaluate(api, h, agent_id, tool, **kw):
    resp = await api.post(
        "/v1/runtime/evaluate",
        json={"agent_id": agent_id, "tool": tool, **kw},
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_implicit_allow_without_policies(api):
    org, h, agent, tool = await _setup(api)
    res = await _evaluate(api, h, agent["id"], "invoice.read")
    assert res["decision"] == "ALLOW"
    assert res["fail_mode"] == "fail_closed"


async def test_org_deny_rule(api):
    org, h, agent, tool = await _setup(api)
    await _bind(
        api, h, org, "FIN-DENY", {"rules": [{"effect": "deny", "actions": ["payment.create"]}]}
    )
    res = await _evaluate(api, h, agent["id"], "payment.create")
    assert res["decision"] == "DENY"
    assert res["policy_id"] == "FIN-DENY"
    assert res["risk_score"] >= 80


async def test_conditional_approval_then_grant(api):
    org, h, agent, tool = await _setup(api)
    await _bind(
        api,
        h,
        org,
        "FIN-004",
        {
            "rules": [
                {
                    "effect": "approval",
                    "actions": ["payment.create"],
                    "when": {"field": "parameters.amount", "op": "gt", "value": 5000},
                    "description": "High-value payment",
                }
            ]
        },
    )

    low = await _evaluate(api, h, agent["id"], "payment.create", parameters={"amount": 10})
    assert low["decision"] == "ALLOW"

    hi = await _evaluate(api, h, agent["id"], "payment.create", parameters={"amount": 48500})
    assert hi["decision"] == "APPROVAL"
    approval_id = hi["approval_request_id"]
    assert approval_id

    # a repeat call reuses the same pending request
    hi2 = await _evaluate(api, h, agent["id"], "payment.create", parameters={"amount": 48500})
    assert hi2["approval_request_id"] == approval_id

    # approve it
    ap = await api.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=h)
    assert ap.status_code == 200 and ap.json()["status"] == "approved"

    # same exact request is now allowed
    granted = await _evaluate(api, h, agent["id"], "payment.create", parameters={"amount": 48500})
    assert granted["decision"] == "ALLOW"

    # a different amount still needs approval
    other = await _evaluate(api, h, agent["id"], "payment.create", parameters={"amount": 99999})
    assert other["decision"] == "APPROVAL"


async def test_rate_limit(api):
    org, h, agent, tool = await _setup(api)
    await _bind(
        api,
        h,
        org,
        "RL",
        {
            "rules": [
                {
                    "effect": "rate_limit",
                    "actions": ["search.web"],
                    "rate_limit": {"max": 2, "window_seconds": 60, "scope": "agent_tool"},
                }
            ]
        },
    )
    assert (await _evaluate(api, h, agent["id"], "search.web"))["decision"] == "ALLOW"
    assert (await _evaluate(api, h, agent["id"], "search.web"))["decision"] == "ALLOW"
    third = await _evaluate(api, h, agent["id"], "search.web")
    assert third["decision"] == "RATE_LIMIT"
    assert third["rate_limit"]["retry_after_seconds"] > 0


async def test_cache_hit_on_second_call(api):
    org, h, agent, tool = await _setup(api)
    await _bind(api, h, org, "PPP", {"rules": [{"effect": "allow", "actions": ["*"]}]})
    first = await _evaluate(api, h, agent["id"], "x.y")
    second = await _evaluate(api, h, agent["id"], "x.y")
    assert first["cache_hit"] is False
    assert second["cache_hit"] is True


async def test_simulate_has_no_side_effects(api):
    org, h, agent, tool = await _setup(api)
    await _bind(
        api,
        h,
        org,
        "SIM",
        {"rules": [{"effect": "approval", "actions": ["payment.create"]}]},
    )
    sim = await api.post(
        "/v1/policies/simulate",
        json={"agent_id": agent["id"], "tool": "payment.create", "parameters": {"amount": 1}},
        headers=h,
    )
    assert sim.status_code == 200
    assert sim.json()["decision"] == "APPROVAL"
    # nothing was created
    approvals = await api.get("/v1/approvals", headers=h)
    assert approvals.json() == []


async def test_policy_validate_endpoint(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    ok = await api.post(
        "/v1/policies/validate",
        json={"spec": {"rules": [{"effect": "deny", "actions": ["*"]}]}},
        headers=h,
    )
    assert ok.json() == {"valid": True, "errors": [], "rule_count": 1}

    bad = await api.post(
        "/v1/policies/validate",
        json={"spec": {"rules": [{"effect": "rate_limit", "actions": ["*"]}]}},
        headers=h,
    )
    assert bad.json()["valid"] is False and bad.json()["errors"]


async def test_runtime_via_api_key(api):
    org, h, agent, tool = await _setup(api)
    created = await api.post(
        f"/v1/organizations/{org}/api-keys",
        json={"name": "runtime", "scopes": ["runtime.evaluate"], "environment": "production"},
        headers=h,
    )
    key = created.json()["key"]
    res = await api.post(
        "/v1/runtime/evaluate",
        json={"agent_id": agent["id"], "tool": "invoice.read"},
        headers=bearer(key),
    )
    assert res.status_code == 200
    assert res.json()["decision"] == "ALLOW"


async def test_runtime_rejects_foreign_agent(api):
    _, h1, agent1, _ = await _setup(api)
    org2, h2, _, _ = await _setup(api)
    resp = await api.post(
        "/v1/runtime/evaluate",
        json={"agent_id": agent1["id"], "tool": "x"},
        headers=h2,
    )
    assert resp.status_code == 404
