from __future__ import annotations

import json

import httpx
import pytest

from agentguard import AgentGuard

AGENT_ID = "11111111-1111-1111-1111-111111111111"


def make_handler(decisions: dict[str, dict]):
    """decisions: tool -> partial runtime response dict."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/agents" and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": AGENT_ID,
                        "name": "TestAgent",
                        "environment": "production",
                        "status": "healthy",
                    }
                ],
            )
        if path == "/v1/agents" and request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "id": AGENT_ID,
                    "name": "TestAgent",
                    "environment": "production",
                    "status": "healthy",
                },
            )
        if path == "/v1/runtime/evaluate":
            body = json.loads(request.content)
            calls.append(body)
            base = {
                "decision": "ALLOW",
                "risk_score": 10,
                "risk_severity": "low",
                "request_id": body.get("request_id", "r"),
                "reasons": [],
                "redactions": [],
                "fail_mode": "fail_closed",
                "cache_hit": False,
                "evaluated_in_ms": 1.0,
            }
            base.update(decisions.get(body["tool"], {}))
            return httpx.Response(200, json=base)
        if path.startswith("/v1/approvals/"):
            return httpx.Response(200, json={"status": "approved"})
        return httpx.Response(404, json={"detail": "not found"})

    handler.calls = calls  # type: ignore[attr-defined]
    return handler


@pytest.fixture
def guard_factory():
    created: list[AgentGuard] = []

    def _make(decisions: dict | None = None, **kw):
        handler = make_handler(decisions or {})
        session = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
        g = AgentGuard(
            api_key="ag_dev_test_secret",
            base_url="http://test",
            agent="TestAgent",
            environment="production",
            session=session,
            **kw,
        )
        g._handler = handler  # type: ignore[attr-defined]
        created.append(g)
        return g

    yield _make
    for g in created:
        g.close()
