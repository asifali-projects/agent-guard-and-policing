# SDKs & CLI (Steps 5, 13)

Covers PRD §36 (CLI), §37 (SDK responsibilities), §38 (examples), §39–40
(TypeScript / .NET), §71 (fast DX).

Three first-party SDKs, all **open-source** (PRD §68) and behaviourally
identical — the same identity model, the same five decisions, the same
fail-safe, and a bundled `agentguard` CLI:

| Language | Package | Directory | Step |
|---|---|---|---|
| Python | `agentguard` (PyPI) | `packages/sdk-python/` | 5 |
| TypeScript / JS | `@agentguard/sdk` (npm) | `packages/sdk-typescript/` | 13 |
| .NET | `AgentGuard.NET` (NuGet) | `packages/sdk-dotnet/` | 13 |

The rest of this page describes the Python SDK in detail; the TypeScript and
.NET ports mirror it — see [§ Parity SDKs](#parity-sdks) for the mapping.

Package: **`agentguard`** in `packages/sdk-python/` — the SDK and the CLI ship
together, so `pip install agentguard` gives you both.

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
agentguard deploy --policies ./policies --fail-on high  # CI gate (PRD §60)
```

`login` never echoes the key; it verifies it against the API before saving with
`chmod 600`.

## Supporting API additions

`GET /v1/audit/events` (filter by action / decision / agent / since, keyset
pagination) and `GET /v1/audit/verify` (recompute the per-org hash chain) —
PRD §33.

<a id="parity-sdks"></a>

## Parity SDKs (Step 13)

`@agentguard/sdk` (TypeScript) and `AgentGuard.NET` (.NET 8) implement the same
contract against `POST /v1/runtime/evaluate`. Both have **zero third-party
runtime dependencies** (built-in `fetch` / `HttpClient` + `System.Text.Json`).

| Concept | Python | TypeScript | .NET |
|---|---|---|---|
| Facade | `AgentGuard(...)` | `new AgentGuard({...})` | `new AgentGuardClient(new AgentGuardOptions {...})` |
| Enforce + run | `@guard.tool` decorator | `guard.tool(fn)` (async wrapper) | `guard.GuardAsync(tool, params, invoke)` |
| Evaluate only | `guard.evaluate(...)` | `guard.evaluate(...)` | `guard.EvaluateAsync(...)` |
| Enforce + redact | `guard.check(...)` | `guard.check(...)` | `guard.CheckAsync(...)` |
| Approval poll | `guard.wait_for_approval(id)` | `guard.waitForApproval(id)` | `guard.WaitForApprovalAsync(id)` |
| Raw control plane | `guard.client.get(...)` | `guard.client.get(...)` | `guard.Api.GetAsync(...)` |
| Config file | `~/.agentguard/config.toml` | `~/.agentguard/config.json` | `~/.agentguard/config.json` |
| Errors | `PolicyDenied` / `ApprovalRequired` / `RateLimited` | same names | `PolicyDeniedException` / `ApprovalRequiredException` / `RateLimitedException` |

The tool wrapper in the TS and .NET SDKs takes a **single object of named
parameters** (rather than binding a Python signature), which is how OpenAI /
LangChain / Semantic Kernel already invoke tools — so `REDACT` can map the
runtime's paths back onto the arguments. .NET also ships
`services.AddAgentGuard(...)` for DI. Each package's `README.md` has the
language-native examples; the CLI (`agentguard login | whoami | agents list |
policy validate | scan | logs | redteam run | mcp scan | deploy`) is identical
across all three.

## Deferred

Framework adapters (LangChain / LangGraph / CrewAI / Semantic Kernel tool
auto-wrapping), async Python SDK, redaction of tool *outputs*, streaming, and
publishing to PyPI / npm / NuGet.
