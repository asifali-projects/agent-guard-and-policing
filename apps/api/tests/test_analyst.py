"""AI Security Analyst — fallback engine, conversations, tenancy, audit (PRD §35).

No ANTHROPIC_API_KEY is set in the test environment, so the deterministic
intent router (`analyst.fallback`) answers every question.
"""

from __future__ import annotations

from .test_auth import bearer, register


async def _agent(api, token: str, name: str, *, risk: int | None = None) -> str:
    resp = await api.post(
        "/v1/agents",
        json={"name": name, "framework": "langgraph", "environment": "production"},
        headers=bearer(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _ask(api, token: str, question: str, conversation_id: str | None = None) -> dict:
    body: dict = {"question": question}
    if conversation_id:
        body["conversation_id"] = conversation_id
    resp = await api.post("/v1/analyst/ask", json=body, headers=bearer(token))
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_suggestions_report_fallback_engine(api):
    _, _, tok = await register(api)
    resp = await api.get("/v1/analyst/suggestions", headers=bearer(tok["access_token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["engine"] == "fallback"
    assert body["enabled"] is True
    assert len(body["suggestions"]) >= 3


async def test_overview_question_creates_conversation(api):
    _, _, tok = await register(api)
    out = await _ask(api, tok["access_token"], "What is our overall security posture?")

    assert out["conversation_id"]
    msg = out["message"]
    assert msg["role"] == "assistant"
    assert msg["engine"] == "fallback"
    assert "score" in msg["content"].lower()
    assert any(c["tool"] == "security_overview" for c in msg["tool_calls"])
    assert msg["citations"]


async def test_multi_turn_conversation_accumulates_messages(api):
    _, _, tok = await register(api)
    token = tok["access_token"]
    first = await _ask(api, token, "security posture?")
    cid = first["conversation_id"]

    second = await _ask(api, token, "which agents are riskiest?", conversation_id=cid)
    assert second["conversation_id"] == cid

    detail = await api.get(f"/v1/analyst/conversations/{cid}", headers=bearer(token))
    assert detail.status_code == 200
    roles = [m["role"] for m in detail.json()["messages"]]
    assert roles == ["user", "assistant", "user", "assistant"]

    convs = await api.get("/v1/analyst/conversations", headers=bearer(token))
    assert convs.status_code == 200
    assert any(c["id"] == cid for c in convs.json())


async def test_riskiest_agents_question_names_the_agent(api):
    _, _, tok = await register(api)
    token = tok["access_token"]
    await _agent(api, token, "PaymentsBot")

    out = await _ask(api, token, "Show me the riskiest agents")
    assert any(c["tool"] == "top_risky_agents" for c in out["message"]["tool_calls"])
    assert "PaymentsBot" in out["message"]["content"]


async def test_explain_decision_without_data_is_graceful(api):
    _, _, tok = await register(api)
    out = await _ask(api, tok["access_token"], "Why was the last action blocked?")
    assert any(c["tool"] == "explain_decision" for c in out["message"]["tool_calls"])
    assert "couldn't find" in out["message"]["content"].lower()


async def test_query_permission_is_required(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    key_resp = await api.post(
        f"/v1/organizations/{org}/api-keys",
        json={"name": "ro", "scopes": ["apikey.read"], "environment": "development"},
        headers=bearer(tok["access_token"]),
    )
    assert key_resp.status_code == 201, key_resp.text
    full_key = key_resp.json()["key"]

    resp = await api.post(
        "/v1/analyst/ask", json={"question": "posture?"}, headers=bearer(full_key)
    )
    assert resp.status_code == 403


async def test_conversations_are_tenant_scoped(api):
    _, _, a = await register(api)
    _, _, b = await register(api)
    made = await _ask(api, a["access_token"], "security posture?")
    cid = made["conversation_id"]

    ok = await api.get(f"/v1/analyst/conversations/{cid}", headers=bearer(a["access_token"]))
    assert ok.status_code == 200
    denied = await api.get(f"/v1/analyst/conversations/{cid}", headers=bearer(b["access_token"]))
    assert denied.status_code == 404


async def test_claude_engine_path_and_graceful_degradation(api, monkeypatch):
    from agentguard_api.analyst import engine
    from agentguard_api.analyst.schemas import AnalystResult
    from agentguard_api.config import get_settings

    _, _, tok = await register(api)
    token = tok["access_token"]

    settings = get_settings()
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test-not-real")

    async def fake_claude(db, s, *, org_id, question, history):
        return AnalystResult(
            answer="Claude says posture is fine.",
            engine="claude",
            citations=[{"tool": "security_overview", "summary": "score 100"}],
            tool_calls=[{"tool": "security_overview", "arguments": {}}],
        )

    monkeypatch.setattr(engine, "_claude_answer", fake_claude)
    ok = await _ask(api, token, "posture?")
    assert ok["message"]["engine"] == "claude"
    assert ok["message"]["content"] == "Claude says posture is fine."

    async def boom(*a, **k):
        raise RuntimeError("model overloaded")

    monkeypatch.setattr(engine, "_claude_answer", boom)
    degraded = await _ask(api, token, "posture?")
    assert degraded["message"]["engine"] == "fallback"
    assert "model was unavailable" in degraded["message"]["content"].lower()


async def test_query_is_audited(api):
    _, _, tok = await register(api)
    token = tok["access_token"]
    await _ask(api, token, "list all agents")

    events = await api.get("/v1/audit/events", headers=bearer(token))
    assert events.status_code == 200
    rows = events.json()
    items = rows["items"] if isinstance(rows, dict) else rows
    assert any(e["action"] == "analyst.query" for e in items)
