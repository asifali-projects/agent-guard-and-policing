"""Risk engine + DLP integration through the runtime and /v1/risk endpoints."""

from __future__ import annotations

from .test_auth import bearer, register
from .test_runtime import _bind, _evaluate


async def _setup(api, *, tool_risk="low", tool_perms=None):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    org = owner["organization_id"]
    agent = (
        await api.post(
            "/v1/agents",
            json={"name": "Agent", "environment": "production"},
            headers=h,
        )
    ).json()
    tool = (
        await api.post(
            "/v1/tools",
            json={"name": "customer.export", "risk": tool_risk, "permissions": tool_perms or []},
            headers=h,
        )
    ).json()
    return org, h, agent, tool


async def test_ssn_is_blocked_by_default_dlp(api):
    org, h, agent, tool = await _setup(api)
    res = await _evaluate(api, h, agent["id"], "customer.export", parameters={"ssn": "123-45-6789"})
    assert res["decision"] == "DENY"
    assert res["data_classification"] == "restricted"
    assert any("DLP" in r for r in res["reasons"])


async def test_email_is_redacted_by_default(api):
    org, h, agent, tool = await _setup(api)
    res = await _evaluate(
        api, h, agent["id"], "customer.export", parameters={"to": "jane@example.com"}
    )
    assert res["decision"] == "REDACT"
    assert res["redactions"] == ["parameters.to"]
    assert res["data_classification"] == "confidential"


async def test_data_policy_override_allows_confidential(api):
    org, h, agent, tool = await _setup(api)
    made = await api.post(
        "/v1/data-security/policies",
        json={"name": "allow-pii", "classification": "confidential", "action": "allow"},
        headers=h,
    )
    assert made.status_code == 201
    res = await _evaluate(
        api, h, agent["id"], "customer.export", parameters={"to": "jane@example.com"}
    )
    assert res["decision"] == "ALLOW"


async def test_risk_score_endpoint_breakdown(api):
    org, h, agent, tool = await _setup(api, tool_risk="critical", tool_perms=["admin"])
    resp = await api.post(
        "/v1/risk/score",
        json={
            "agent_id": agent["id"],
            "tool": "customer.export",
            "parameters": {"ssn": "123-45-6789", "records": 50000},
            "context": {"destination": "external"},
        },
        headers=h,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert {f["name"] for f in body["factors"]} == {
        "identity",
        "permission",
        "tool",
        "data",
        "destination",
        "behavior",
        "historical",
    }
    assert body["risk_score"] >= 65
    assert body["severity"] in ("high", "critical")
    assert body["decision"] in ("APPROVAL", "BLOCK")
    assert body["factors"] and abs(sum(f["weight"] for f in body["factors"]) - 1.0) < 1e-6


async def test_risk_escalates_low_policy_decision(api):
    org, h, agent, tool = await _setup(api, tool_risk="critical", tool_perms=["admin"])
    # confidential data allowed, so DLP won't escalate — risk must.
    await api.post(
        "/v1/data-security/policies",
        json={"name": "allow-pii", "classification": "confidential", "action": "allow"},
        headers=h,
    )
    res = await _evaluate(
        api,
        h,
        agent["id"],
        "customer.export",
        parameters={"to": "jane@example.com", "records": 50000},
        context={"destination": "external"},
    )
    assert res["decision"] in ("APPROVAL", "DENY")
    assert res["risk_severity"] in ("high", "critical")
    assert any("risk score" in r for r in res["reasons"])


async def test_never_exfil_key_always_blocked(api):
    org, h, agent, tool = await _setup(api)
    # even with an allow-everything policy + allow data policy, a private key is blocked
    await _bind(api, h, org, "ALLOWALL", {"rules": [{"effect": "allow", "actions": ["*"]}]})
    for label in ("restricted", "confidential"):
        await api.post(
            "/v1/data-security/policies",
            json={"name": f"allow-{label}", "classification": label, "action": "allow"},
            headers=h,
        )
    res = await _evaluate(
        api,
        h,
        agent["id"],
        "customer.export",
        parameters={"blob": "-----BEGIN RSA PRIVATE KEY-----\nMIIBjunk"},
    )
    assert res["decision"] == "DENY"


async def test_data_security_scan_endpoint(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    resp = await api.post(
        "/v1/data-security/scan",
        json={"payload": {"customer": {"ssn": "123-45-6789", "email": "x@y.com"}}},
        headers=h,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["classification"] == "restricted"
    assert body["action"] == "block"
    assert {f["detector"] for f in body["findings"]} == {"us_ssn", "email"}
    # samples are masked
    assert all("*" in f["sample"] for f in body["findings"])
