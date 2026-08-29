# Red-Team Engine (Step 6)

Covers PRD §17 (MCP security), §18–22 (red-team platform, categories, engine,
continuous, finding management).

A first-class module (PRD §18), not an add-on: `agentguard_api/redteam/`.

## What it attacks

The engine replays adversarial tool-call attempts through the **runtime decision
core** — the same DLP + policy + risk stack that protects real agents — and
checks whether the decision matches the *expected security behaviour*. It is
testing the customer's **configuration** (policies, data policies, agent setup),
which is exactly what §18–22 are about.

```
Target Agent → Attack Planner → Generator → Sandbox (core_decision, no writes)
             → Observation → Evaluator → Risk Classification → Finding
```

`core_decision` (`runtime/core.py`) was extracted from `evaluate_runtime` so the
sandbox produces the real verdict without creating approvals, audit rows, or
telemetry.

## Catalog (PRD §19)

21 techniques across all six categories, each with adversarial variants and the
set of decisions that count as **defended**:

| Category | Techniques |
|---|---|
| Prompt | direct injection, system-prompt extraction, indirect injection, goal hijacking |
| Tool | unauthorized tool, parameter manipulation, tool chaining, privilege escalation |
| Data | PII leakage, secret leakage, bulk exfiltration, cross-tenant access |
| Agent | excessive autonomy, memory poisoning, agent-to-agent manipulation, approval bypass |
| MCP | tool poisoning, permission abuse |
| Availability | recursive execution, denial of wallet, excessive API usage |

Profiles (PRD §18): `quick` (~8 core), `standard` (all, 1 variant),
`deep` / `enterprise` (all, up to 3 variants), `custom` (caller picks categories
or technique ids).

## Evaluator

`passed = observed_decision ∈ technique.defended`. A failure becomes a
`redteam_tests` row (Attack ID, Category, Technique, Input, Expected Behaviour,
Observed Behaviour, Severity, passed — PRD §20) and, per technique, a
`redteam_findings` row. Findings are **upserted**: an open finding for the same
`(agent, title)` is refreshed by a later assessment rather than duplicated.

Severity = the technique's base severity, escalated by the observed risk score.

## Finding management (PRD §22)

```
GET  /v1/redteam/findings?status=&severity=&agent_id=&category=
GET  /v1/redteam/findings/{id}
POST /v1/redteam/findings/{id}/suppress          {reason}
POST /v1/redteam/findings/{id}/false-positive
POST /v1/redteam/findings/{id}/assign            {owner_id}
POST /v1/redteam/findings/{id}/retest            → re-runs the technique; resolves if now defended
POST /v1/redteam/findings/{id}/policy            → creates + binds a remediation Policy
POST /v1/redteam/findings/{id}/incident          → opens an Incident
```

`.../policy` synthesises a spec from the technique (deny / approval / rate-limit
rule on the involved tools), creates it with key `RT-<TECHNIQUE>`, and binds it
org-wide. Re-running `retest` then resolves the finding.

## Assessment endpoints

```
GET  /v1/redteam/techniques
POST /v1/redteam/assessments        {agent_id, profile, environment?, categories?, technique_ids?, trigger?}
GET  /v1/redteam/assessments[?agent_id=]
GET  /v1/redteam/assessments/{id}
GET  /v1/redteam/assessments/{id}/tests
```

Assessments run **inline** in the request today (each test is a sub-millisecond
`core_decision`). Deep / enterprise profiles move to the worker in Step 8.

## Continuous / CI (PRD §21)

```
agentguard redteam run --agent FinanceAgent --profile quick --fail-on high
```

exits non-zero when any open finding is at or above the threshold — drop it into
a CI job as a deploy gate. The GitHub Action wrapper (`agentguard/security-action`,
PRD §60) is Step 9.

## MCP security (PRD §17)

Minimal inventory + heuristic scan:

```
GET/POST/PATCH/DELETE  /v1/mcp/servers
POST                   /v1/mcp/servers/{id}/scan
```

Scan flags: untrusted server, excessive permissions, dangerous filesystem
access, credential exposure (basic-auth URL), external dependencies, unpinned
version, poisoned metadata. It sets the server's `risk` and moves it to
`review_required` / `quarantined`. Behavioural MCP checks (unexpected network
calls) arrive with the detection service in Step 8.

```
agentguard mcp scan [--server <name>]
```

## Deferred

LLM-assisted attack generation, driving a live agent endpoint directly,
adaptive/iterative attacks, the worker-backed deep assessments and continuous
triggers (Step 8), the GitHub Action (Step 9).
