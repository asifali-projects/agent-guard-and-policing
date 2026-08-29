# Python SDK & CLI (Step 5)

Covers PRD §36 (CLI), §37 (SDK responsibilities), §38 (examples), §71 (fast DX).

Package: **`agentguard`** in `packages/sdk-python/` — the SDK and the CLI ship
together, so `pip install agentguard` gives you both. **Open-source** (PRD §68).

## SDK

```python
from agentguard import AgentGuard

guard = AgentGuard(
    api_key="ag_live_...",          # or AGENTGUARD_API_KEY / config file
    agent="FinanceAgent",
    environment="production",
)

@guard.tool
def send_email(to: str, subject: str, body: str) -> None:
    ...                              # runs only if the runtime says ALLOW
```

Config resolution order (each field independently): explicit arg → env var
(`AGENTGUARD_API_KEY`, `AGENTGUARD_BASE_URL`, `AGENTGUARD_AGENT`, …) →
`~/.agentguard/config.toml` → default.

### What the decorator does

On every call it binds the arguments, sends
`POST /v1/runtime/evaluate { agent_id, tool, action, parameters }`, and acts on
the decision (PRD §24):

| Decision | Behaviour |
|---|---|
| `ALLOW` | call the function |
| `DENY` | raise `PolicyDenied` |
| `APPROVAL` | raise `ApprovalRequired` (`.approval_request_id`) |
| `REDACT` | mask the flagged argument paths, then call the function |
| `RATE_LIMIT` | raise `RateLimited` (`.retry_after_seconds`) |

All raise from `AgentGuardError`; each carries `.result` (the full
`DecisionResult`).

### Responsibilities (PRD §37)

- **Identity** — `agent` name + `environment` are resolved to an agent id on
  first use, registering the agent if it doesn't exist.
- **Tracing** — a `request_id` is generated per call and threaded through to the
  API for end-to-end correlation.
- **Tool interception** — `@guard.tool` / `guard.protect(agent)` (wraps a
  discoverable `agent.tools` list).
- **Policy evaluation / runtime protection** — delegated to the runtime API
  (deterministic, no LLM).
- **Telemetry** — the API emits to ClickHouse; the SDK just correlates.

### Fail-safe (PRD §59)

If the runtime API is unreachable:

- `fail_mode="closed"` (default) → `PolicyDenied`
- `fail_mode="open"` → the function runs

### Lower-level API

```python
result = guard.evaluate("payment.create", {"amount": 48500})   # no enforcement
result, params = guard.check("payment.create", {"amount": 48500})  # enforce + redact
status = guard.wait_for_approval(err.approval_request_id)       # poll until decided
guard.client.get("/v1/agents")                                  # raw control-plane calls
```

## CLI (`agentguard`)

```
agentguard login                     # save an API key to ~/.agentguard/config.toml
agentguard init                      # write agentguard.toml in the project
agentguard whoami
agentguard agents list
agentguard policy validate rules.json
agentguard scan                      # per-agent risk posture summary
agentguard logs [--decision deny]    # recent audit events

agentguard redteam run --agent X --profile quick --fail-on high   # CI gate (PRD §21)
agentguard mcp scan [--server NAME]
agentguard deploy                    # Step 9
```

`login` never echoes the key; it verifies it against the API before saving with
`chmod 600`.

## Supporting API additions

`GET /v1/audit/events` (filter by action / decision / agent / since, keyset
pagination) and `GET /v1/audit/verify` (recompute the per-org hash chain) —
PRD §33.

## Deferred

Framework adapters (LangChain / LangGraph / CrewAI tool auto-wrapping),
async SDK, redaction of tool *outputs*, the `deploy` command (Step 9),
TypeScript + .NET SDKs (Step 13).
