# AI Security Analyst (Step 12)

PRD §35 — a read-only natural-language interface over the AgentGuard control
plane. Ask *"which agents are riskiest?"*, *"why was the last action blocked?"*,
*"has anything tried to exfiltrate data this week?"* and get an answer grounded
in your own data.

## Engine

Two interchangeable back-ends behind one API:

| Engine | When | How |
|--------|------|-----|
| `claude` | `ANTHROPIC_API_KEY` is set | Claude runs a tool-use loop (`AGENTGUARD_ANALYST_MODEL`, default `claude-sonnet-4-5`, up to `AGENTGUARD_ANALYST_MAX_ITERS` iterations) over the read-only tool library |
| `fallback` | no key, or the model call fails | `analyst/fallback.py` — a deterministic intent router maps the question to 1–2 tools and templates the answer |

The fallback path is always available, so the feature (and its tests) never
depend on network or a key. A model failure degrades to the fallback with a
one-line notice rather than erroring.

## Tools (`analyst/tools.py`)

Every tool is a deterministic, **organization-scoped** query. `org_id` is bound
from the caller's principal — never from the model. Nothing writes.

`security_overview` · `list_agents` · `get_agent` · `top_risky_agents` ·
`list_findings` · `list_incidents` · `list_threats` · `search_audit` ·
`explain_decision`

`search_audit` is safe to quote — the audit log stores payload **hashes**, not
payloads (PRD §75).

## API — `/v1/analyst` (`analyst.query` permission)

```
GET    /v1/analyst/suggestions                → { enabled, engine, suggestions[] }
POST   /v1/analyst/ask   { question, conversation_id? }
GET    /v1/analyst/conversations
GET    /v1/analyst/conversations/{id}          full thread
DELETE /v1/analyst/conversations/{id}
```

`analyst.query` is granted to `owner`, `admin`, `security_admin`,
`security_analyst`, `developer`, and `auditor` (not `billing_admin`).

Every `ask` is:

- **persisted** — `analyst_conversations` + `analyst_messages` (migration
  `d7dd2cdb788f`); each assistant message stores the tools it called, its
  citations, and which engine produced it.
- **rate-limited** — `AGENTGUARD_ANALYST_HOURLY_QUOTA` (default 60) per org,
  tracked in Redis; a Redis outage fails open.
- **audited** — an `analyst.query` audit event records the engine and the tool
  names used.

## Deployment

Implemented in `apps/api/agentguard_api/analyst/`. `analyst/asgi.py` is a
standalone ASGI app (health + `/v1/analyst` only) so the analyst can run as its
own container — the compose `ai-analyst` service uses the API image with
`uvicorn agentguard_api.analyst.asgi:app` (port `ANALYST_PORT`, default 8020).

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `ANTHROPIC_API_KEY` | — | enables the Claude engine |
| `AGENTGUARD_ANALYST_MODEL` | `claude-sonnet-4-5` | model id for the loop |
| `AGENTGUARD_ANALYST_MAX_ITERS` | `6` | max tool-use round trips |
| `AGENTGUARD_ANALYST_HOURLY_QUOTA` | `60` | questions per org per hour (0 = unlimited) |
| `AGENTGUARD_ANALYST_ENABLED` | `true` | master switch |

## Deferred

Streaming responses, ClickHouse-backed analytics tools, saved/scheduled
questions, per-user (not per-org) quota, citation deep-links into the UI.
