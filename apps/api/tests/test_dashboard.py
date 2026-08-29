"""Dashboard summary (PRD §11)."""

from __future__ import annotations

from .test_auth import bearer, register
from .test_runtime import _evaluate, _setup


async def test_dashboard_summary_shape(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    resp = await api.get("/v1/dashboard/summary", headers=h)
    assert resp.status_code == 200
    body = resp.json()
    assert body["security_score"] == 100  # nothing wrong yet
    assert body["assets"] == {"agents": 0, "mcp_servers": 0, "tools": 0}
    assert body["top_risky_agents"] == []


async def test_dashboard_reflects_findings_and_blocks(api):
    org, h, agent, tool = await _setup(api)
    # DLP blocks the SSN -> DENY, audited
    await _evaluate(api, h, agent["id"], "payment.create", parameters={"ssn": "123-45-6789"})
    # bare agent -> the assessment finds undefended techniques
    await api.post(
        "/v1/redteam/assessments",
        json={"agent_id": agent["id"], "profile": "quick"},
        headers=h,
    )

    body = (await api.get("/v1/dashboard/summary", headers=h)).json()
    assert body["assets"]["agents"] == 1
    assert body["assets"]["tools"] == 1
    threats = body["threats"]
    assert threats["critical"] + threats["high"] + threats["medium"] >= 1
    assert body["security_score"] < 100
    assert body["runtime"]["blocked_24h"] >= 1
    assert body["top_risky_agents"][0]["name"] == "FinanceAgent"
