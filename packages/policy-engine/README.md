# packages/policy-engine

Deterministic policy evaluation library (Python). **Open-source** component
(PRD §68).

The critical-path authorization decision must **not** depend on an LLM
(PRD §25). This library is a pure function:

```
(agent, tool, action, parameters, context, policy_set) -> Decision
```

where `Decision ∈ {ALLOW, DENY, APPROVAL, REDACT, RATE_LIMIT}` (PRD §24).

Policy hierarchy (PRD §23): Organization → Environment → Agent → Tool → Action,
with conditions such as `amount > 5000`, `destination = external`,
`records > 100`, `data.classification = confidential`.

Implemented in **Step 3**. Consumed by `apps/api` (runtime endpoint) and the
SDKs (local enforcement).
