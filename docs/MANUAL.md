# AgentGuard — Product Manual

Everything the platform does, and how to use it. For setup and operations see
[`RUNNING.md`](RUNNING.md); for internals see [`ARCHITECTURE.md`](ARCHITECTURE.md)
and the per-subsystem docs linked throughout.

---

## Contents

1. [What AgentGuard is](#1-what-agentguard-is)
2. [Core concepts](#2-core-concepts)
3. [Getting started](#3-getting-started)
4. [Identity & Access](#4-identity--access)
5. [Agent & Tool inventory](#5-agent--tool-inventory)
6. [MCP servers](#6-mcp-servers)
7. [Policy Engine](#7-policy-engine)
8. [Runtime enforcement](#8-runtime-enforcement)
9. [Risk Engine](#9-risk-engine)
10. [Data Security / DLP](#10-data-security--dlp)
11. [Red-Team Engine](#11-red-team-engine)
12. [Behavioral Detection & Threats](#12-behavioral-detection--threats)
13. [Incidents & Response](#13-incidents--response)
14. [Agent Graph & Blast Radius](#14-agent-graph--blast-radius)
15. [Audit Log](#15-audit-log)
16. [Integrations, Webhooks & CI/CD](#16-integrations-webhooks--cicd)
17. [Billing & Usage](#17-billing--usage)
18. [AI Security Analyst](#18-ai-security-analyst)
19. [Multi-Region](#19-multi-region)
20. [The Dashboard](#20-the-dashboard)
21. [SDKs & CLI](#21-sdks--cli)
22. [API reference summary](#22-api-reference-summary)
23. [Permission reference](#23-permission-reference)
24. [Glossary](#24-glossary)

---

## 1. What AgentGuard is

> The AI model decides what it *wants* to do. AgentGuard decides whether it is
> *allowed* to do it.

AgentGuard is a security & governance layer that sits between AI agents and the
tools and data they act on. Every tool call an agent makes is evaluated — in
**deterministic, sub-50 ms, no-LLM** fashion — against your policies, a risk
score, and data-loss rules, and returns one of five decisions. It also gives you
an inventory of every agent, an offensive red-team engine, behavioral anomaly
detection, incident response, an immutable audit trail, and an AI analyst to
query all of it in natural language.

It **integrates with** your IAM, SIEM, DLP and ticketing — it does not replace
them.

### The three planes

| Plane | Responsibility |
|---|---|
| **Control** | tenants, users, RBAC, agents, tools, MCP servers, policies, API keys, billing |
| **Security** | policy evaluation, risk scoring, DLP, red-team, detection, approvals |
| **Data** | event ingestion, telemetry, analytics, the audit hash-chain |

---

## 2. Core concepts

| Concept | Meaning |
|---|---|
| **Organization** | your tenant. Everything is scoped to one. Pinned to one **data-residency region** at creation. |
| **Member / Role** | a user's membership in an org carries exactly one of 7 built-in roles → a permission set. |
| **Agent** | a registered AI agent: name + environment (`development`/`staging`/`production`), framework, model, fail-mode, status, risk score. |
| **Agent identity** | every agent gets a stable identity string (`agent:finance-prod`), a **trust level**, and an owner. |
| **Tool** | a capability an agent can invoke (`payment.create`, `search.web`). Inventoried, with a permission scope. |
| **MCP server** | a Model Context Protocol server an agent connects to; inventoried and heuristically scanned. |
| **Policy** | a JSON rule set (`deny` / `approval` / `allow` lists + conditions). **Bound** at a level of the hierarchy. |
| **Binding** | attaches a policy at org / environment / agent / tool / action scope. |
| **Decision** | the runtime output: `ALLOW`, `DENY`, `APPROVAL`, `REDACT`, or `RATE_LIMIT`. |
| **Risk score** | 0–100 composite from 7 weighted factors, computed per evaluation. |
| **Finding** | a managed weakness from a red-team assessment, with a lifecycle and remediation actions. |
| **Threat** | a detected anomaly / attack signal (behavioral drift, prompt injection …). |
| **Incident** | a tracked security event with a lifecycle and automatic response actions. |
| **Approval request** | a paused action awaiting a human decision. |
| **Audit event** | an append-only, hash-chained record — tamper-evident per org. |
| **API key** | `ag_<env>_<publicid>_<secret>` — how SDKs and CI authenticate. |
| **Region** | `us` / `eu` / `me` / `apac` — a fully isolated deployment; an org's data never leaves it. |

---

## 3. Getting started

**As an operator (dashboard):**

1. Open the dashboard, choose **Create account**, pick your data-residency
   region, and register. You become the **Owner** of a new organization.
2. **Agents** → your first agent appears automatically the first time an SDK
   registers it, or add one manually.
3. **Policies** → create a policy, validate it, bind it (start at org scope).
4. Watch the **Dashboard** "Am I safe?" summary and the **Audit Log**.

**As a developer (SDK):**

```python
from agentguard import AgentGuard

guard = AgentGuard(api_key="ag_live_…", agent="FinanceAgent", environment="production")

@guard.tool
def send_email(to: str, subject: str, body: str) -> None:
    ...   # runs only if the runtime returns ALLOW; REDACT masks flagged args
```

First call registers `FinanceAgent`, sends
`POST /v1/runtime/evaluate`, and enforces the decision. See
[§21](#21-sdks--cli) and [`SDK.md`](SDK.md).

**In CI:**

```bash
agentguard deploy --policies ./policies --fail-on high
```

Validates every policy and runs a red-team pass; exits non-zero on a blocking
finding. See [§16](#16-integrations-webhooks--cicd).

---

## 4. Identity & Access

Full detail: [`AUTH.md`](AUTH.md).

### Principals

Every request authenticates as one of:

| Kind | Credential | Permissions from |
|---|---|---|
| **user** | `Authorization: Bearer <JWT access token>` | membership role in the token's org |
| **api_key** | `Authorization: Bearer ag_…` or `X-API-Key: ag_…` | the key's scopes (default `runtime.evaluate`) |

### Sessions

- Access token: JWT, HS256, 15 min, stateless.
- Refresh token: opaque, 30 days, only its SHA-256 is stored; **rotated** on
  every refresh with **reuse detection** (a replayed token revokes the whole
  family).
- Device tracking: `GET /v1/auth/sessions` lists active sessions;
  `DELETE …/{id}` revokes one; `logout` with `all_sessions` revokes all.

### MFA (TOTP)

`enroll` → `activate` (with a code). Afterwards `login` returns an `mfa_token`
challenge; exchange it + a code at `/v1/auth/mfa/verify`. MFA-enabled accounts
must sign in via the `agentguard` CLI or the API, not the dashboard form.

### OAuth & Enterprise SSO

- **OAuth** (Google, Microsoft) — enabled when the provider's client id/secret
  are configured. `GET /v1/auth/oauth/{provider}/authorize` → provider →
  callback links an external identity and issues a session.
- **SAML 2.0 / OIDC** (per-org, admin-configured) — domain-based discovery
  (`POST /v1/auth/sso/discover`), IdP redirect, OIDC callback / SAML ACS, JIT
  user provisioning, optional **enforced SSO** (blocks password login for the
  domain). Configure at **Administration → SSO & SCIM**. See [`SSO.md`](SSO.md).

### SCIM 2.0 provisioning

`/scim/v2/Users` + `/scim/v2/Groups` (RFC 7643/7644) with a per-org bearer
token. Deactivating a user in your IdP revokes their AgentGuard access; a SCIM
group whose name matches a role (`security_admin`, "AgentGuard Developer", …)
drives that member's role. See [`SCIM.md`](SCIM.md).

### Roles & permissions

7 built-in roles over a 32-permission catalog — see [§23](#23-permission-reference).

### API keys (PRD §52)

Format `ag_<env>_<publicid>_<secret>`, `env` ∈ `dev|stg|live`. Only the Argon2
hash of the secret is stored; the full key is shown once. Per-key: scopes (≤ the
creator's permissions), environment, expiry, IP allowlist, `last_used_at`,
`usage_count`, revoke. Manage at **Developer → API Keys**.

### Organizations & members

`GET/POST /v1/organizations`, `…/{id}/members` CRUD. A user can belong to
several orgs and switch the active one
(`POST /v1/auth/organizations/{id}/switch`). The last Owner cannot be removed or
demoted.

---

## 5. Agent & Tool inventory

`/v1/agents`, `/v1/tools`. Dashboard: **Security → Agents / Tools**.

**Agent** fields: name, kind (`ai_agent`, `mcp_server`, `rag_application`,
`coding_agent`, `multi_agent_system`), framework (`openai`, `langgraph`,
`langchain`, `crewai`, `semantic_kernel`, `mcp`, `custom`), model, environment,
owner team, `fail_mode` (`fail_open` / `fail_closed` / `fail_safe`), status
(`healthy` / `warning` / `high` / `critical` / `paused` / `archived`),
`risk_score`, tags.

Every agent has an **identity** (`agent:<slug>`), a **trust level**
(`untrusted` → `privileged`), and an owner (PRD §15). SDKs auto-register an
agent on first use.

The agent detail page shows the posture breakdown, recent findings, incidents,
tools, and the risk-factor contributions.

**Tools** carry a permission scope (`read` / `write` / `execute` / `admin`) and
agent-tool grants. A tool that isn't inventoried raises the risk score of calls
that use it.

---

## 6. MCP servers

`/v1/mcp/servers` + `POST …/{id}/scan`. Dashboard: **Security → MCP Servers**.

Register the MCP servers your agents connect to. The heuristic **scan** (PRD
§17) flags issues (excessive scopes, unpinned versions, suspicious tool names …)
and sets a status: `active` / `review_required` / `quarantined` / `disabled`.
CLI: `agentguard mcp scan [--server NAME]`.

---

## 7. Policy Engine

Full detail: [`POLICY.md`](POLICY.md). The engine is
`packages/policy-engine` — **pure Python, no I/O, no LLM, no database**.

### Policy spec (`policies.spec`, JSON)

```json
{
  "rules": [
    { "effect": "approval",
      "actions": ["payment.create", "payment.*:execute"],
      "when": { "all": [
        { "field": "parameters.amount", "op": "gt", "value": 5000 },
        { "field": "context.destination", "op": "eq", "value": "external" }
      ]},
      "description": "High-value external payment" },
    { "effect": "redact", "actions": ["*"], "redactions": ["parameters.ssn"] },
    { "effect": "rate_limit", "actions": ["search.web"],
      "rate_limit": { "max": 100, "window_seconds": 60, "scope": "agent_tool" } }
  ],
  "default_effect": "allow"
}
```

- **`actions`** — fnmatch globs matched against `tool` and `tool:action`;
  `"*"` matches everything.
- **`when`** — condition tree (`all` / `any` / `not` / leaf `{field, op,
  value}`). Ops: `eq ne gt gte lt lte in not_in contains startswith endswith
  matches glob exists`. Fields are dotted paths into `parameters` / `context` /
  `agent` / `tool` / `action` / `environment` / `data`. A missing field never
  crashes evaluation.

### Hierarchy & precedence

Bind a policy at **org → environment → agent → tool → action** scope
(`/v1/policies/{id}/bindings`). Across every matching rule of every applicable
policy:

```
deny > approval > rate_limit > redact > allow > default_effect > implicit allow
```

`redact` unions all redaction paths; `rate_limit` takes the first matching
rule's spec.

### Authoring workflow

- `POST /v1/policies/validate` — structural check, returns `{valid, rule_count,
  errors}`. CLI: `agentguard policy validate rules.json`.
- `POST /v1/policies/simulate` — run a hypothetical evaluation against the
  org's live policy set without persisting anything.
- Policies are **versioned** (`policy_versions`); the active set is Redis-cached
  and invalidated on change.

Dashboard: **Governance → Policies** (list, edit, validate, bindings).

---

## 8. Runtime enforcement

Full detail: [`POLICY.md`](POLICY.md), [`RISK_DLP.md`](RISK_DLP.md). Endpoint:
`POST /v1/runtime/evaluate` (permission `runtime.evaluate`).

### Request

```jsonc
{
  "agent_id": "…uuid…",
  "tool": "payment.create",
  "action": "execute",              // default "execute"
  "parameters": { "amount": 48500 },
  "context": { "destination": "external" },
  "request_id": "…",                // caller-supplied, for end-to-end tracing
  "data_classification": "confidential"  // optional hint
}
```

### Pipeline (side-effect-free core, then stateful wrap)

```
DLP scan → policy evaluation → risk scoring → combine → decision
        → (stateful) rate-limit consume · approval binding · emit event · audit · usage meter
```

### Response

```jsonc
{
  "decision": "APPROVAL",           // ALLOW | DENY | APPROVAL | REDACT | RATE_LIMIT
  "risk_score": 72,
  "risk_severity": "high",
  "request_id": "…",
  "policy_id": "…", "policy_keys": ["FIN-004"],
  "reasons": ["High-value external payment"],
  "redactions": ["parameters.ssn"],         // on REDACT
  "approval_request_id": "…",               // on APPROVAL
  "rate_limit": { "max": 100, "window_seconds": 60, "retry_after_seconds": 41 },
  "fail_mode": "fail_closed",
  "cache_hit": true,
  "evaluated_in_ms": 3.1
}
```

### The five decisions

| Decision | SDK behaviour |
|---|---|
| `ALLOW` | call the tool |
| `DENY` | raise `PolicyDenied` |
| `APPROVAL` | raise `ApprovalRequired` (`.approval_request_id`); poll `wait_for_approval` |
| `REDACT` | mask the flagged parameter paths, then call the tool |
| `RATE_LIMIT` | raise `RateLimited` (`.retry_after_seconds`) |

### Fail-safe (PRD §59)

If the runtime API is unreachable, the SDK applies the agent's `fail_mode`:
`fail_closed` (default) → deny; `fail_open` → run; `fail_safe` → per-tool table.

### Approvals

`APPROVAL` decisions create an `approval_requests` row. Reviewers act at
**Security → Approvals** or via `POST /v1/approvals/{id}/approve|reject`
(permission `approval.decide`). The SDK's `wait_for_approval(id)` polls until
decided.

### Rate limiting

Fixed-window counters in Redis, scoped `agent` / `tool` / `agent_tool`. A
`RATE_LIMIT` decision returns `retry_after_seconds`.

---

## 9. Risk Engine

Full detail: [`RISK_DLP.md`](RISK_DLP.md). `POST /v1/risk/score` for an ad-hoc
assessment; otherwise it runs inside every `evaluate`.

Composite 0–100 from **7 weighted factors**:

| Factor | Signal |
|---|---|
| `identity` | agent trust level, whether it's registered |
| `permission` | is the tool granted to this agent |
| `tool` | is the tool inventoried; its permission scope |
| `data` | sensitivity of the parameters (from the DLP scan) |
| `destination` | where the action sends data (internal / external / unspecified) |
| `behavior` | anomaly score vs. the agent's baseline (Step 8) |
| `historical` | the agent's recent finding / incident history |

A **severe behavioral anomaly floors** the composite (anomaly ≥ 90 → risk ≥ 82).
`risk_severity` buckets: `info` / `low` / `medium` / `high` / `critical`.

---

## 10. Data Security / DLP

Full detail: [`RISK_DLP.md`](RISK_DLP.md). Dashboard: **Governance → Data
Security**. Endpoints under `/v1/data-security`.

### Detectors (15)

`email`, `us_ssn`, `phone`, `iban`, `jwt`, `aws_access_key`, `gcp_api_key`,
`openai_key`, `github_token`, `slack_token`, `agentguard_key`, `private_key`,
`basic_auth`, `credit_card` (Luhn-checked), `generic_secret`. Pure regex, run on
`parameters` on every evaluation. `POST /v1/data-security/scan` scans arbitrary
text.

### Classifications & data policies

- **Classification rules** (`/v1/data-security/classifications`) — tag data
  `public` / `internal` / `confidential` / `restricted`.
- **Data policies** (`/v1/data-security/policies`) — map a classification to a
  DLP action: `allow` / `redact` / `block` / `approval`. Without a matching
  policy, built-in defaults apply.

### NEVER_EXFIL

A hard block: certain detector hits (private keys, `agentguard_key`, …) to an
**external** destination are denied regardless of policy.

---

## 11. Red-Team Engine

Full detail: [`REDTEAM.md`](REDTEAM.md). Dashboard: **Security → Red Team**.
Endpoints under `/v1/redteam`.

### What it does

Replays a catalog of **21 attack techniques** across the 6 PRD §19 categories
(`prompt`, `tool`, `data`, `agent`, `mcp`, `availability`) through the
**side-effect-free** `core_decision` sandbox — no real tool ever runs — and
judges each result against the technique's expected-defended set.

### Assessments

`POST /v1/redteam/assessments { agent_id, profile, environment }`. Profiles:
`quick` / `standard` / `deep` / `enterprise` / `custom`. Runs inline; the
summary reports `passed / failed / total` and a severity breakdown. CLI:
`agentguard redteam run --agent X --profile quick --fail-on high`.

### Findings (PRD §22)

A failed technique becomes a `redteam_findings` row with a lifecycle
(`open` → `triaged` → `retest` / `suppressed` / `false_positive` / `resolved`)
and actions:

| Action | Endpoint |
|---|---|
| Generate a remediation **policy** | `POST …/findings/{id}/policy` |
| Open an **incident** | `POST …/findings/{id}/incident` |
| **Retest** | `POST …/findings/{id}/retest` |
| **Suppress** / **assign** / mark **false-positive** | `POST …/findings/{id}/{suppress,assign,false-positive}` |

---

## 12. Behavioral Detection & Threats

Full detail: [`DETECTION.md`](DETECTION.md). Dashboard: **Security → Threats**.

Every runtime evaluation upserts the agent's `behavior_profiles` row (tool
counts, volumes, destinations, classifications seen, recent tool sequence). A
pure anomaly scorer compares the current call to that baseline; the score feeds
the risk engine's `behavior` factor, and a high score **raises a threat** and
can **auto-open an incident**.

Threats (`/v1/threats`) carry a kind, severity, status
(`open` / `investigating` / `resolved` / `false_positive`) and a link to the
agent and any incident. `POST /v1/threats/{id}/resolve` closes one.

> The synchronous detector runs in-API. Heavier ClickHouse-backed baselines,
> n-gram sequence models, and cross-agent campaign detection are the worker-tier
> roadmap (`services/detection`).

---

## 13. Incidents & Response

Full detail: [`DETECTION.md`](DETECTION.md). Dashboard: **Security →
Incidents**. Endpoints under `/v1/incidents`.

An incident has a key (`INC-####`), title, severity, a lifecycle
(`detected` → `investigating` → `contained` → `resolved` → `closed`), an
optional linked agent, and a **timeline** of every status change and action.

### Response actions (`POST /v1/incidents/{id}/actions`)

| Action | Effect |
|---|---|
| `pause_agent` | the runtime **denies every call** from that agent until resumed |
| `block_tool` | an auto-generated deny policy blocks that tool |

Transitions: `POST /v1/incidents/{id}/transition`.

---

## 14. Agent Graph & Blast Radius

Full detail: [`DETECTION.md`](DETECTION.md). Dashboard: **Security → Agents →
(agent) → Graph**.

- `GET /v1/agents/{id}/graph` — the agent's connections to tools, MCP servers,
  and other agents.
- `GET /v1/agents/{id}/blast-radius` — what a compromise of this agent could
  reach (transitive tool / data / destination exposure).

---

## 15. Audit Log

Full detail: [`AUTH.md`](AUTH.md). Dashboard: **Observability → Audit Log**.

Every security-relevant action writes an **append-only, hash-chained**
`audit_events` row: each row's `entry_hash` covers the previous row's hash plus
this row's canonical content, forming a per-organization chain serialised by a
Postgres advisory lock. Rows are never updated or deleted by the application,
and payloads are stored as **hashes**, not raw content (PRD §75).

- `GET /v1/audit/events` — filter by action / decision / agent / since, keyset
  pagination. CLI: `agentguard logs [--decision deny]`.
- `GET /v1/audit/events.csv` — export.
- `GET /v1/audit/verify` — recompute and validate the chain; returns whether it
  is intact.

Recorded: auth (register / login / SSO), org & member changes, API-key
lifecycle, every non-allow runtime decision, red-team actions, incident
transitions, analyst queries, SCIM changes.

---

## 16. Integrations, Webhooks & CI/CD

Full detail: [`INTEGRATIONS.md`](INTEGRATIONS.md). Dashboard: **Developer →
Integrations**.

### Event bus

`events/bus.publish()` fans **canonical events** (agent blocked, approval
required, threat detected, incident created/updated, red-team completed, agent
registered) to:

- **Webhooks** (`/v1/webhooks`) — HMAC-signed (`X-AgentGuard-Signature`),
  per-webhook event filter, delivery stats, `POST …/{id}/test`.
- **Integrations** (`/v1/integrations`) — Slack, PagerDuty, generic SIEM, and a
  provider catalog (identity / siem / devops / notifications / ticketing /
  cloud).

Delivery is best-effort and inline — it never blocks a runtime decision.

### CI/CD

- `agentguard deploy --policies ./dir --fail-on <sev>` — validates every policy
  spec, red-teams the target agents, writes an optional Markdown PR comment, and
  **exits non-zero** on a blocking finding (PRD §60).
- A composite **GitHub Action** at `.github/actions/agentguard` wraps it.
- `agentguard redteam run --fail-on <sev>` is the lighter single-agent gate
  (PRD §21).

---

## 17. Billing & Usage

Full detail: [`INTEGRATIONS.md`](INTEGRATIONS.md). Dashboard: **Administration →
Billing** (permission `org.billing`).

- **Plans** (`GET /v1/billing/plans`): Community / Developer / Team / Business /
  Enterprise, each with advisory metered limits (agents, users,
  runtime actions, red-team tests …).
- **Subscription** (`GET/POST /v1/billing/subscription`): the org's current
  plan and status (`trialing` / `active` / `past_due` / `canceled`).
- **Usage**: Redis counters incremented on the hot path
  (`runtime_actions`, `redteam_tests`, `agents`, …), surfaced against the plan's
  limits. Limits are **advisory** — over-limit is reported, not hard-blocked.

---

## 18. AI Security Analyst

Full detail: [`ANALYST.md`](ANALYST.md). Dashboard: **Security Analyst**.
Endpoints under `/v1/analyst` (permission `analyst.query`).

Ask questions in plain language — *"which agents are riskiest?"*, *"why was the
last action blocked?"*, *"has anything tried to exfiltrate data this week?"* —
and get an answer grounded in your own data.

- **Engine**: when `ANTHROPIC_API_KEY` is set, Claude runs a tool-use loop over
  **9 read-only, org-scoped** query tools (`security_overview`, `list_agents`,
  `get_agent`, `top_risky_agents`, `list_findings`, `list_incidents`,
  `list_threats`, `search_audit`, `explain_decision`). Without a key, a
  deterministic intent router answers — so the feature always works.
- **Read-only** — no tool writes; `org_id` is bound from your principal, never
  the model.
- Conversations are persisted; each answer records the tools it called, its
  citations, and which engine produced it. Per-org hourly quota; every query is
  audited.

Endpoints: `POST /ask { question, conversation_id? }`, `GET /conversations`,
`GET/DELETE /conversations/{id}`, `GET /suggestions`.

---

## 19. Multi-Region

Full detail: [`MULTI_REGION.md`](MULTI_REGION.md),
[ADR 0002](adr/0002-multi-region-data-residency.md).

**One deployment serves exactly one region** (`us` / `eu` / `me` / `apac`).
Each region is a complete, isolated stack; an organization is pinned to its
home region **at creation** and its data never leaves.

- The customer chooses residency by **signing up at that region's URL**. The
  dashboard sign-up form has a region picker and redirects accordingly.
- `GET /v1/regions` (public) advertises every region's API/web URL.
- A request to the wrong region returns **`421 Misdirected Request`** with
  `X-AgentGuard-Region-Url` pointing to the right endpoint; the dashboard turns
  this into a "continue there →" link.
- `Organization.region` is immutable. `/v1/auth/me` exposes `region` (this
  deployment) and `active_region` (your org's home).

---

## 20. The Dashboard

Next.js 14, the PRD §8 information architecture. Full detail: [`WEB.md`](WEB.md).

| Group | Pages |
|---|---|
| — | **Dashboard** ("Am I safe?" — security score, assets, threats, 24 h runtime, top risky agents), **Security Analyst** |
| Security | Agents (+ detail: posture, tools, graph), Tools, MCP Servers, Red Team, Findings, Threats, Incidents, Approvals |
| Governance | Policies (+ validate + bindings), Data Security |
| Observability | Audit Log (+ chain verify) |
| Developer | API Keys, Integrations (+ webhooks) |
| Administration | Team, SSO & SCIM, Billing |

Header shows the active org, your role, and the **data-residency region badge**.
Auth handles token refresh on 401; a 421 shows a wrong-region redirect.

---

## 21. SDKs & CLI

Full detail: [`SDK.md`](SDK.md). Three behaviourally identical SDKs, each with a
bundled `agentguard` CLI.

| | Python | TypeScript | .NET |
|---|---|---|---|
| Package | `agentguard` (PyPI) | `@agentguard/sdk` (npm) | `AgentGuard.NET` (NuGet) |
| Enforce + run | `@guard.tool` | `guard.tool(fn)` | `guard.GuardAsync(tool, params, invoke)` |
| Evaluate only | `guard.evaluate` | `guard.evaluate` | `guard.EvaluateAsync` |
| Enforce + redact | `guard.check` | `guard.check` | `guard.CheckAsync` |
| Approval poll | `guard.wait_for_approval` | `guard.waitForApproval` | `guard.WaitForApprovalAsync` |
| Raw API | `guard.client.get/post` | `guard.client.get/post` | `guard.Api.GetAsync/PostAsync` |
| Config file | `~/.agentguard/config.toml` | `~/.agentguard/config.json` | `~/.agentguard/config.json` |

Config resolution (each field): explicit arg → env var (`AGENTGUARD_API_KEY`,
`AGENTGUARD_BASE_URL`, `AGENTGUARD_AGENT`, `AGENTGUARD_ENVIRONMENT`,
`AGENTGUARD_FAIL_MODE`, `AGENTGUARD_TIMEOUT`) → config file → default.

### CLI (identical across languages)

```
agentguard login                     # save an API key
agentguard whoami
agentguard agents list
agentguard policy validate rules.json
agentguard scan                      # per-agent risk posture
agentguard logs [--decision deny]
agentguard redteam run --agent X --profile quick --fail-on high
agentguard mcp scan [--server NAME]
agentguard deploy --policies ./policies --fail-on high
```

.NET also ships `services.AddAgentGuard(...)` for ASP.NET Core DI.

---

## 22. API reference summary

Base: `/v1`. Interactive docs at `/docs` (Swagger) and `/redoc`. All endpoints
are organization-scoped via the principal unless noted **public**.

| Area | Endpoints |
|---|---|
| Meta | `GET /` · `GET /healthz` · `GET /readyz` · **public** `GET /v1/regions` |
| Auth | `POST /v1/auth/{register,login,refresh,logout}` · `GET /v1/auth/me` · `GET/DELETE /v1/auth/sessions` · `POST /v1/auth/mfa/{enroll,activate,verify,disable}` · `POST /v1/auth/organizations/{id}/switch` |
| OAuth / SSO | `GET /v1/auth/oauth/providers` · `GET /v1/auth/oauth/{provider}/{authorize,callback}` · `POST /v1/auth/sso/discover` · `GET /v1/auth/sso/{cid}/{login,callback}` · `POST /v1/auth/sso/{cid}/acs` |
| Organizations | `GET/POST /v1/organizations` · `GET/PATCH /v1/organizations/{id}` · `…/{id}/members` · `…/{id}/api-keys` · `…/{id}/sso` · `…/{id}/scim` |
| SCIM | `/scim/v2/{ServiceProviderConfig,ResourceTypes,Schemas}` · `/scim/v2/Users` · `/scim/v2/Groups` |
| Inventory | `GET/POST /v1/agents` · `…/{id}` · `…/{id}/graph` · `…/{id}/blast-radius` · `GET/POST /v1/tools` · `/v1/mcp/servers` (+ `…/{id}/scan`) |
| Policy & runtime | `GET/POST /v1/policies` (+ `/validate`, `/simulate`, `…/{id}/bindings`) · `POST /v1/runtime/evaluate` · `POST /v1/risk/score` |
| Data security | `/v1/data-security/{detectors,classifications,policies,scan}` |
| Red team | `/v1/redteam/{assessments,findings,techniques}` (+ finding actions) |
| Detection & IR | `GET /v1/threats` (+ `…/{id}/resolve`) · `/v1/incidents` (+ `…/{id}/{actions,transition}`) · `/v1/approvals` (+ `…/{id}/{approve,reject}`) |
| Observability | `GET /v1/dashboard/summary` · `GET /v1/audit/{events,events.csv,verify}` |
| Integrations | `/v1/integrations` (+ `/catalog`) · `/v1/webhooks` (+ `…/{id}/test`) |
| Billing | `GET /v1/billing/plans` · `GET/POST /v1/billing/subscription` |
| Analyst | `POST /v1/analyst/ask` · `GET /v1/analyst/{suggestions,conversations}` · `GET/DELETE /v1/analyst/conversations/{id}` |

---

## 23. Permission reference

7 built-in roles over 32 permission codes. `require_permission("code")` gates
each endpoint; MFA-pending or no-active-org tokens are rejected first.

| Role | Grants |
|---|---|
| **owner** | all 32 |
| **admin** | all except `org.billing` |
| **security_admin** | agents/tools/MCP/policies manage · findings/incidents/threats · approvals decide · data manage · audit + analytics + analyst |
| **security_analyst** | all `*.read` + `analytics.read` + `audit.read` + `analyst.query` |
| **developer** | agents/tools/MCP manage · policy.read · redteam.run · own API keys · integrations · analytics + analyst · `runtime.evaluate` |
| **auditor** | all `*.read` + `audit.read` + `analytics.read` + `analyst.query` |
| **billing_admin** | `org.read`, `org.billing` only |

Full code list: `apps/api/agentguard_api/rbac/catalog.py` (the source of truth).
Categories: organization, developer, security, governance, observability,
runtime.

---

## 24. Glossary

| Term | Definition |
|---|---|
| **Action** | the verb on a tool call (`execute`, `read`, …); part of policy matching (`tool:action`). |
| **Binding** | attaches a policy at a scope in the org → env → agent → tool → action hierarchy. |
| **Blast radius** | the transitive set of tools / data / destinations a compromised agent could reach. |
| **Canonical event** | one of the fixed event types the event bus fans to webhooks/integrations. |
| **Core decision** | the side-effect-free part of runtime evaluation (DLP → policy → risk → combine), shared by the runtime and the red-team sandbox. |
| **Fail mode** | what the SDK does when the runtime is unreachable: `fail_open` / `fail_closed` / `fail_safe`. |
| **Hash chain** | the tamper-evident structure of the audit log — each row hashes the previous. |
| **Home region** | the region an org's data lives in; set at creation, immutable. |
| **JIT provisioning** | creating a user automatically on first SSO / SCIM sign-in. |
| **NEVER_EXFIL** | the hard DLP block: secrets to an external destination are always denied. |
| **Principal** | the resolved identity of a request — a user (JWT) or an API key — with an org and a permission set. |
| **Profile** | a red-team assessment depth (`quick` / `standard` / `deep` / `enterprise` / `custom`). |
| **Redaction path** | a dotted parameter path the runtime says to mask (`parameters.body`). |
| **Trust level** | an agent identity's assurance tier (`untrusted` → `privileged`), a risk-engine input. |

---

### Where to go next

- Setup & operations → [`RUNNING.md`](RUNNING.md)
- Internals → [`ARCHITECTURE.md`](ARCHITECTURE.md), [`DATA_MODEL.md`](DATA_MODEL.md)
- Per subsystem → [`AUTH`](AUTH.md) · [`POLICY`](POLICY.md) · [`RISK_DLP`](RISK_DLP.md) · [`REDTEAM`](REDTEAM.md) · [`DETECTION`](DETECTION.md) · [`INTEGRATIONS`](INTEGRATIONS.md) · [`SDK`](SDK.md) · [`WEB`](WEB.md) · [`SSO`](SSO.md) · [`SCIM`](SCIM.md) · [`ANALYST`](ANALYST.md) · [`MULTI_REGION`](MULTI_REGION.md)
- Decisions → [`adr/`](adr/)
- Plan vs. PRD → [`ROADMAP.md`](ROADMAP.md)
