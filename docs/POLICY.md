# Policy Engine & Runtime API (Step 3)

Covers PRD §23 (policy hierarchy), §24 (decision engine), §25 (runtime guard),
§29 (approval binding), §42 (runtime API), §46 (policy cache).

## The engine — `packages/policy-engine`

Pure Python, **no I/O, no LLM, no database** (PRD §25). One function:

```python
from agentguard_policy import evaluate, EvaluationInput
result = evaluate(EvaluationInput(tool="payment.create", parameters={"amount": 48500}), policies)
# result.decision -> Decision.deny | .approval | .rate_limit | .redact | .allow
```

It decides *what the policy says*. Stateful obligations (rate-limit counters,
approval lookup) are resolved by the runtime layer.

### Policy spec (`policies.spec` JSON)

```json
{
  "rules": [
    {
      "effect": "approval",
      "actions": ["payment.create", "payment.*:execute"],
      "when": {
        "all": [
          {"field": "parameters.amount", "op": "gt", "value": 5000},
          {"field": "context.destination", "op": "eq", "value": "external"}
        ]
      },
      "description": "High-value external payment"
    },
    {"effect": "redact", "actions": ["*"], "redactions": ["parameters.ssn"]},
    {"effect": "rate_limit", "actions": ["search.web"],
     "rate_limit": {"max": 100, "window_seconds": 60, "scope": "agent_tool"}}
  ],
  "default_effect": "allow"
}
```

- **`actions`** — fnmatch globs matched against the tool name (`payment.create`)
  and `tool:action` (`payment.create:execute`). `"*"` matches everything.
- **`when`** — condition tree: `all` / `any` / `not` / leaf
  `{field, op, value}`. Ops: `eq ne gt gte lt lte in not_in contains startswith
  endswith matches glob exists`. Fields are dotted paths into
  `parameters` / `context` / `agent` / `tool` / `action` / `environment` / `data`.
  A missing field never crashes evaluation.

### Precedence (PRD §23–24)

Across every matching rule from every applicable policy:

```
deny  >  approval  >  rate_limit  >  redact  >  allow  >  default_effect  >  implicit allow
```

`redact` unions all redaction paths. `rate_limit` returns the first matching
rule's spec.

### Hierarchy (PRD §23)

Policies are bound at a scope; more specific scopes carry more weight when
resolving `default_effect` and duplicate policy keys:

```
organization (0)  <  environment (1)  <  agent (2)  <  tool (3)  <  action (4)
```

## Runtime API — `POST /v1/runtime/evaluate` (PRD §42)

Requires the `runtime.evaluate` permission (API keys carry it by default).

```jsonc
// request
{ "agent_id": "…", "tool": "payment.create", "action": "execute",
  "parameters": { "amount": 48500 }, "context": { "destination": "external" },
  "request_id": "…" }

// response
{ "decision": "APPROVAL", "risk_score": 87, "request_id": "…",
  "policy_id": "FIN-004", "policy_keys": ["FIN-004"],
  "reasons": ["FIN-004#0: High-value external payment"],
  "redactions": [], "approval_request_id": "…", "rate_limit": null,
  "fail_mode": "fail_closed", "cache_hit": true, "evaluated_in_ms": 2.9 }
```

Path: identify agent (must be in the caller's org) → load policy set → engine →
resolve rate-limit / approval → risk score → emit → respond.

- **Policy cache** (PRD §46) — all enabled bound policies for an org are cached
  in Redis as one blob keyed by `pver:{org}` (bumped on any policy/binding
  write), 30 s TTL. Per request it's filtered to this env/agent/tool/action.
- **Rate limiting** — Redis fixed-window counter. Under budget → `ALLOW` (with
  `rate_limit.remaining`); over → `RATE_LIMIT` with `retry_after_seconds`.
- **Approval** (PRD §29) — an `APPROVAL` decision creates (or reuses) an
  `approval_requests` row bound to the **exact** `agent + action + SHA-256 of
  parameters`, with a 1 h expiry. Once approved, the identical call returns
  `ALLOW`; any parameter change needs a new approval.
- **Risk score** — a placeholder derived from tool risk + decision floor. The
  real multi-factor risk engine replaces it in **Step 4**.
- **Telemetry** — each decision is emitted best-effort to ClickHouse
  `runtime_decisions`; failures never block the decision. Non-`ALLOW` decisions
  also append to the `audit_events` hash chain.
- **Fail-safe** (PRD §59) — the agent's `fail_mode` is returned so the SDK knows
  what to do if AgentGuard itself is unreachable. Within the endpoint, an
  evaluation error is fail-closed.

## Management endpoints

```
GET/POST        /v1/policies
GET/PATCH/DELETE /v1/policies/{id}
GET/POST        /v1/policies/{id}/bindings
DELETE          /v1/policies/{id}/bindings/{bid}
POST            /v1/policies/validate      # CLI: agentguard policy validate
POST            /v1/policies/simulate      # dry run — no side effects

GET             /v1/approvals?status=pending
GET             /v1/approvals/{id}
POST            /v1/approvals/{id}/approve
POST            /v1/approvals/{id}/reject

GET/POST/PATCH/DELETE  /v1/agents        # minimal inventory (rich detail: Step 7)
GET/POST/PATCH/DELETE  /v1/tools
```

Every policy write also records a `policy_versions` row.

## Deferred

Multi-factor risk engine (Step 4), DLP detectors that produce the redaction
paths (Step 4), Kafka-fronted event ingestion (Step 8), CI policy gate
(`agentguard policy validate` in a GitHub Action — Step 9).
