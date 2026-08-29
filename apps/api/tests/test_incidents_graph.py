"""Incidents + response actions + agent graph / blast radius (PRD §30–32)."""

from __future__ import annotations

from .test_auth import bearer, register
from .test_runtime import _evaluate


async def _agent(api, h, name="GraphAgent"):
    return (
        await api.post("/v1/agents", json={"name": name, "environment": "production"}, headers=h)
    ).json()


async def test_incident_lifecycle_and_pause_blocks_runtime(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)

    inc = await api.post(
        "/v1/incidents",
        json={"title": "Suspicious activity", "severity": "high", "agent_id": agent["id"]},
        headers=h,
    )
    assert inc.status_code == 201
    iid = inc.json()["id"]
    assert inc.json()["status"] == "detected"

    # pause the agent as a response action
    act = await api.post(f"/v1/incidents/{iid}/actions", json={"action": "pause_agent"}, headers=h)
    assert act.status_code == 200 and act.json()["agent_status"] == "paused"

    # runtime now denies everything for that agent
    res = await _evaluate(api, h, agent["id"], "invoice.read")
    assert res["decision"] == "DENY"
    assert "paused" in res["reasons"][0]

    # lifecycle: detected -> investigating -> contained -> resolved -> closed
    for st in ("investigating", "contained", "resolved", "closed"):
        r = await api.post(f"/v1/incidents/{iid}/transition", json={"status": st}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == st

    # illegal transition from closed
    bad = await api.post(
        f"/v1/incidents/{iid}/transition", json={"status": "investigating"}, headers=h
    )
    assert bad.status_code == 409

    detail = await api.get(f"/v1/incidents/{iid}", headers=h)
    kinds = [e["kind"] for e in detail.json()["events"]]
    assert "opened" in kinds and "action" in kinds and kinds.count("status_change") == 4


async def test_block_tool_action_creates_deny_policy(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)
    inc = await api.post(
        "/v1/incidents",
        json={"title": "Tool abuse", "severity": "critical", "agent_id": agent["id"]},
        headers=h,
    )
    iid = inc.json()["id"]
    act = await api.post(
        f"/v1/incidents/{iid}/actions",
        json={"action": "block_tool", "tool": "payment.create"},
        headers=h,
    )
    assert act.status_code == 200
    res = await _evaluate(api, h, agent["id"], "payment.create")
    assert res["decision"] == "DENY"


async def test_agent_graph_and_blast_radius(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)
    await api.post(
        "/v1/tools",
        json={"name": "database.export", "risk": "critical", "destination": "external"},
        headers=h,
    )

    # generate some activity so the behaviour profile has edges
    for _ in range(3):
        await _evaluate(
            api,
            h,
            agent["id"],
            "customer.read",
            parameters={"records": 3},
            context={"destination": "internal"},
        )
    await _evaluate(
        api,
        h,
        agent["id"],
        "database.export",
        parameters={"records": 10},
        context={"destination": "external"},
    )

    graph = await api.get(f"/v1/agents/{agent['id']}/graph", headers=h)
    assert graph.status_code == 200
    types = {n["type"] for n in graph.json()["nodes"]}
    assert "agent" in types and "tool" in types and "destination" in types
    assert any(e["kind"] == "calls" for e in graph.json()["edges"])

    blast = await api.get(f"/v1/agents/{agent['id']}/blast-radius", headers=h)
    assert blast.status_code == 200
    b = blast.json()
    assert b["tools"] >= 2
    assert b["databases"] >= 1
    assert "external" in b["external_destinations"]
    assert b["potential_impact"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


async def test_audit_csv_export(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    resp = await api.get("/v1/audit/events.csv", headers=h)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.strip().splitlines()
    assert lines[0].startswith("occurred_at,action,")
    assert any("auth.register" in ln for ln in lines[1:])
