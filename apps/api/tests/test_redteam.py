"""Red-team engine + finding management (PRD §18–22)."""

from __future__ import annotations

from .test_auth import bearer, register


async def _agent(api, h):
    return (
        await api.post(
            "/v1/agents",
            json={"name": "TargetAgent", "environment": "production"},
            headers=h,
        )
    ).json()


async def test_assessment_finds_undefended_techniques(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)

    resp = await api.post(
        "/v1/redteam/assessments",
        json={"agent_id": agent["id"], "profile": "quick"},
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    a = resp.json()
    assert a["status"] == "completed"
    assert a["summary"]["total"] >= 6
    assert a["summary"]["failed"] >= 1

    tests = await api.get(f"/v1/redteam/assessments/{a['id']}/tests", headers=h)
    assert tests.status_code == 200
    techs = {t["technique"] for t in tests.json()}
    assert techs  # something ran

    findings = await api.get("/v1/redteam/findings", headers=h)
    assert findings.status_code == 200
    titles = {f["title"] for f in findings.json()}
    # a bare org has no policy on payment tools -> injection / param-manip are findings
    assert any("injection" in t.lower() or "parameter" in t.lower() for t in titles)
    # DLP already blocks secret leakage, so that must NOT be a finding
    assert not any("Secret" in t for t in titles)


async def test_remediation_policy_then_retest_resolves(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)

    await api.post(
        "/v1/redteam/assessments",
        json={
            "agent_id": agent["id"],
            "profile": "custom",
            "technique_ids": ["tool.parameter_manipulation"],
        },
        headers=h,
    )
    findings = (await api.get("/v1/redteam/findings", headers=h)).json()
    assert findings, "expected an undefended finding"
    fid = findings[0]["id"]

    made = await api.post(f"/v1/redteam/findings/{fid}/policy", headers=h)
    assert made.status_code == 201, made.text
    assert made.json()["key"].startswith("RT-")

    retest = await api.post(f"/v1/redteam/findings/{fid}/retest", headers=h)
    assert retest.status_code == 200
    assert retest.json()["passed"] is True
    assert retest.json()["status"] == "resolved"


async def test_finding_lifecycle_actions(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)
    await api.post(
        "/v1/redteam/assessments",
        json={
            "agent_id": agent["id"],
            "profile": "custom",
            "technique_ids": ["prompt.direct_injection"],
        },
        headers=h,
    )
    fid = (await api.get("/v1/redteam/findings", headers=h)).json()[0]["id"]

    inc = await api.post(f"/v1/redteam/findings/{fid}/incident", headers=h)
    assert inc.status_code == 201
    assert inc.json()["key"].startswith("INC-")

    sup = await api.post(
        f"/v1/redteam/findings/{fid}/suppress", json={"reason": "accepted risk"}, headers=h
    )
    assert sup.status_code == 200 and sup.json()["status"] == "suppressed"

    me = (await api.get("/v1/auth/me", headers=h)).json()
    asg = await api.post(
        f"/v1/redteam/findings/{fid}/assign", json={"owner_id": me["id"]}, headers=h
    )
    assert asg.json()["owner_id"] == me["id"]


async def test_defended_org_has_fewer_findings(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    agent = await _agent(api, h)

    # deny everything
    pol = await api.post(
        "/v1/policies",
        json={
            "key": "LOCKDOWN",
            "name": "deny all",
            "spec": {"rules": [{"effect": "deny", "actions": ["*"]}]},
        },
        headers=h,
    )
    await api.post(
        f"/v1/policies/{pol.json()['id']}/bindings",
        json={"scope_type": "organization"},
        headers=h,
    )

    a = await api.post(
        "/v1/redteam/assessments",
        json={"agent_id": agent["id"], "profile": "standard"},
        headers=h,
    )
    summary = a.json()["summary"]
    # with a blanket deny, almost everything is defended
    assert summary["passed"] >= summary["failed"]


async def test_techniques_catalogue(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    resp = await api.get("/v1/redteam/techniques", headers=h)
    assert resp.status_code == 200
    cats = {t["category"] for t in resp.json()}
    assert {"prompt", "tool", "data", "agent", "mcp", "availability"} <= cats


async def test_redteam_tenant_isolation(api):
    _, _, a1 = await register(api)
    h1 = bearer(a1["access_token"])
    agent = await _agent(api, h1)
    made = await api.post(
        "/v1/redteam/assessments",
        json={"agent_id": agent["id"], "profile": "quick"},
        headers=h1,
    )
    aid = made.json()["id"]

    _, _, a2 = await register(api)
    h2 = bearer(a2["access_token"])
    assert (await api.get(f"/v1/redteam/assessments/{aid}", headers=h2)).status_code == 404
