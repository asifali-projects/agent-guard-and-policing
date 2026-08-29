# Architecture

This document tracks the **target** architecture from the PRD and the current
state of the code. It is updated as each step lands.

## 1. Product principle

> The AI model decides what it *wants* to do. AgentGuard decides whether it is
> *allowed* to do it.

AgentGuard is the AI-agent-aware layer that sits between agents and the tools /
data they act on. It **integrates with** IAM, SIEM, DLP, WAF, EDR and CSPM — it
does not replace them (PRD §3).

## 2. Planes (PRD §6)

```
                         AGENTGUARD CLOUD
       ┌───────────────────────┼────────────────────────┐
 CONTROL PLANE            SECURITY PLANE           DATA PLANE
 Agent registry          Red-team engine          Event stream
 Identity                Threat engine            Telemetry
 Organizations           Risk engine              Analytics
 Policies                DLP                      Audit
 RBAC / Billing          Runtime guard / Approval
       └───────────────────────┼────────────────────────┘
                        AGENTGUARD GATEWAY
              ┌────────────────┼────────────────┐
          AI Agent            MCP              API
                     Enterprise Systems
```

| Plane | Owns | Code |
|-------|------|------|
| Control | tenants, identity, agents, tools, policies, RBAC, billing | `apps/api` |
| Security | policy evaluation, risk, DLP, red-team, detection, approval | `packages/policy-engine`, `services/*` |
| Data | event ingestion, telemetry, analytics, audit | `apps/workers`, ClickHouse |

## 3. Request paths

### Runtime critical path (must be fast + deterministic — PRD §25, §58)

```
Agent → AgentGuard SDK / Gateway → Authenticate → Identify agent → Identify tool
      → Validate parameters → Policy check → Risk → DLP → Decision → Tool
```

Target: **p95 < 50 ms** for cached deterministic policy checks. No LLM call on
this path. Fail-safe behaviour is configurable per tool (fail-open / fail-closed
/ fail-safe-by-tool — PRD §59).

### Asynchronous path

Every decision emits an event → Redpanda → workers → ClickHouse (analytics),
Postgres (audit), detection service (behavioral anomaly). None of this blocks
the agent.

## 4. Datastores (PRD §44–48)

| Store | Role | Never used for |
|-------|------|----------------|
| PostgreSQL (+pgvector) | source of truth: orgs, agents, tools, MCP, policies, findings, incidents, approvals, API keys, billing | high-volume event log |
| ClickHouse | `agent_events`, `tool_calls`, `security_events`, `runtime_decisions`, `behavior_events` | authorization decisions |
| Redis | policy cache, agent-config cache, rate limiting, session + approval state, short-lived risk data | durable storage |
| Redpanda (Kafka API) | runtime event transport, at-least-once | query engine |
| Qdrant | threat intel, attack patterns, semantic incident search, red-team corpus | **authorization decisions** |
| MinIO / S3 | red-team evidence, reports, exports, compliance artifacts, large payloads | anything needed synchronously |

Data minimization by design (PRD §75): store hash + metadata + classification +
risk + decision + trace by default, not full prompts / payloads. Evidence
verbosity (redacted / metadata-only / full) is customer-controlled.

## 5. Tenancy & authz (PRD §49–50)

Every resource carries `organization_id`. Authorization chain:
`User → Organization → Role → Resource`. Roles: Owner, Admin, Security Admin,
Security Analyst, Developer, Auditor, Billing Admin. Enterprise tier can get a
dedicated database / deployment.

## 6. Tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| API | FastAPI (Python 3.11), async SQLAlchemy | one language across API + AI/detection/red-team; fast iteration |
| Workers | Python | shares models with the API |
| Policy engine | Pure Python library | deterministic, embeddable in API and SDKs |
| Web | Next.js 14 (App Router), TypeScript | PRD §53 |
| Infra (local) | Docker Compose | PRD §55 backing services |
| Infra (prod) | Kubernetes / EKS | PRD §55–56 |
| Observability | OpenTelemetry | PRD §57 |

> The PRD (§54) also floats ASP.NET Core for the API. We chose Python-first for
> a single-language core; the .NET SDK (§39) is still delivered in Step 13. This
> decision is recorded in [`adr/0001-python-first-backend.md`](adr/0001-python-first-backend.md).

## 7. Current state (through Step 9)

**Step 0** — repo layout, `infra/docker-compose.yml` (all six backing services
with health checks), `apps/api` FastAPI skeleton (`/`, `/healthz`, `/readyz`,
OpenAPI), `apps/web` Next.js skeleton, CI, this document set.

**Step 1** — the full control-plane data model:

- 36 SQLAlchemy 2.0 models under `apps/api/agentguard_api/models/`, one module
  per domain, covering every table in PRD §44.
- Deterministic constraint naming; VARCHAR-backed enums (adding a value is a
  code change, not an `ALTER TYPE`).
- Alembic (async) with the initial migration; `alembic check` gates drift in CI.
- Append-only, hash-chained `audit_events` (PRD §33).
- ClickHouse event store — `agent_events`, `tool_calls`, `security_events`,
  `runtime_decisions`, `behavior_events` (PRD §45) — applied by
  `python -m agentguard_api.events.migrate`.

See [`DATA_MODEL.md`](DATA_MODEL.md).

**Step 2** — authentication, tenancy, RBAC ([`AUTH.md`](AUTH.md)):

- Password (Argon2id) + OAuth (Google / Microsoft) login; JWT access tokens +
  rotating opaque refresh tokens with reuse detection and device tracking;
  TOTP MFA.
- `Principal` abstraction — a request authenticates as a user or an API key, both
  resolving to an org + a permission set. `require_permission(...)` gates
  endpoints.
- Built-in 7-role RBAC over a 31-permission catalog (`rbac/catalog.py`), seeded
  into the DB by `python -m agentguard_api.rbac.seed`.
- API key system (PRD §52): `ag_<env>_<id>_<secret>`, Argon2-hashed, scoped
  (≤ creator's permissions), IP allowlist, expiry, revoke.
- Audit log writer with per-org hash chain + `verify_chain()`.
- 24 endpoints under `/v1/auth`, `/v1/organizations`, `.../api-keys`.

**Step 3** — policy engine + runtime guard ([`POLICY.md`](POLICY.md)):

- `packages/policy-engine` — pure, deterministic `evaluate(input, policies)`;
  policy spec, condition trees, precedence (deny > approval > rate_limit >
  redact > allow), scope hierarchy. No I/O, no LLM. 21 tests.
- `POST /v1/runtime/evaluate` (§42) — the critical path. Redis-cached policy set
  per org (versioned, §46), Redis fixed-window rate limiting, exact-match
  approval binding (§29), placeholder risk score (Step 4 replaces), best-effort
  ClickHouse `runtime_decisions` emit, audit on non-allow.
- `/v1/policies` (CRUD + bindings + `validate` + `simulate`), `/v1/approvals`
  (list / approve / reject), minimal `/v1/agents` + `/v1/tools` inventory.

**Step 4** — risk engine + DLP ([`RISK_DLP.md`](RISK_DLP.md)):

- `agentguard_api/dlp/` — pure detectors (15 patterns, Luhn-checked cards,
  key-name secret context), payload walk with JSON-path findings, classification
  → action resolution with per-org `DataPolicy` overrides and a `NEVER_EXFIL`
  hard block for credentials.
- `agentguard_api/risk/` — 7-factor weighted score (identity, permission, tool,
  data, destination, behavior, historical) → `{risk_score, severity, decision}`.
  Behavioral factor is a heuristic pending Step 8.
- Both wired into `/v1/runtime/evaluate`: DLP + policy + risk produce candidate
  decisions resolved by the same precedence; the real risk score replaces the
  Step 3 placeholder; classification feeds the policy engine.
- `/v1/risk/score` (factor breakdown), `/v1/data-security/{scan,detectors,
  classifications,policies}`.

**Step 5** — Python SDK + CLI ([`SDK.md`](SDK.md)):

- `packages/sdk-python` (`agentguard`) — sync `httpx` client; `@guard.tool` binds
  arguments and calls `/v1/runtime/evaluate`, enforcing the decision
  (deny→raise, approval→raise with id, redact→mask args + run, rate_limit→raise).
  Agent identity auto-resolves/registers. Config: arg > env > `~/.agentguard/config.toml`.
  Fail-safe honours `fail_mode` when the API is unreachable.
- The `agentguard` CLI ships in the same package: `login`, `init`, `whoami`,
  `agents list`, `policy validate`, `scan`, `logs` (+ stubs for `redteam` / `mcp`
  / `deploy`).
- API: `GET /v1/audit/events` (filters + keyset pagination) and
  `GET /v1/audit/verify` (per-org hash-chain recompute).

**Step 6** — red-team engine ([`REDTEAM.md`](REDTEAM.md)):

- `runtime/core.py` — `core_decision` (DLP + policy + risk, **no writes**)
  extracted so both `evaluate_runtime` and the red-team sandbox share one path.
- `redteam/` — 21-technique catalog across all six PRD §19 categories, a
  generator/sandbox runner, an evaluator that judges the observed decision
  against each technique's "defended" set, and upserted `redteam_findings`.
- `/v1/redteam` — assessments (inline), technique catalog, and the PRD §22
  finding actions: remediation-policy synthesis, incident creation, retest,
  suppress, false-positive, assign.
- `mcp/` — minimal MCP server inventory + a heuristic §17 scan
  (`/v1/mcp/servers`, `.../scan`).
- CLI: `agentguard redteam run --fail-on <sev>` (CI gate, PRD §21) and
  `agentguard mcp scan`.

**Step 7** — web dashboard ([`WEB.md`](WEB.md)):

- `apps/web` built out: Next.js 14 + Tailwind + TanStack Query. Auth
  (`lib/api.ts` refreshes tokens on 401), the PRD §8 sidebar, and pages for the
  dashboard, agent inventory + detail (with the 7-factor posture breakdown),
  findings + §22 actions, policies, approvals, red-team, audit, data security,
  MCP, API keys, and team — RBAC-gated in the UI.
- API: `GET /v1/dashboard/summary` (§11) and CORS middleware.

Verified end to end in a browser: register → run red-team → remediate a finding
(Create policy → Retest → resolved).

**Step 8** — detection, incidents, graph ([`DETECTION.md`](DETECTION.md)):

- `detection/` — per-agent `behavior_profiles` (upserted on every runtime call)
  + a pure anomaly scorer that replaces the Step 4 behaviour heuristic in the
  risk engine and floors the composite risk on a severe anomaly.
- Anomalous calls raise `threats` (deduped) and auto-open `Incident`s at
  score ≥ 85.
- `incidents/` — `/v1/incidents` + `/v1/threats`: lifecycle transitions,
  timeline, and response actions (`pause_agent` → runtime denies the agent
  entirely; `block_tool` → auto deny policy).
- `graph/` — `/v1/agents/{id}/graph` and `/blast-radius` (PRD §31–32) built from
  the behaviour profile + grants.
- `GET /v1/audit/events.csv` (PRD §33). Frontend: Threats, Incidents, and an
  agent Graph tab.

**Step 9** — integrations, CI/CD, billing ([`INTEGRATIONS.md`](INTEGRATIONS.md)):

- `events/bus.py` — `publish()` fans canonical events (PRD §43) to HMAC-signed
  webhooks + Slack / PagerDuty / SIEM integrations, best-effort inline; wired at
  every source (blocks, threats, incidents, assessments, registrations).
- `integrations/` — `/v1/integrations` + `/v1/webhooks` CRUD, provider catalog,
  webhook test.
- `billing/` — Redis usage counters on the hot path, `/v1/billing` (plans,
  subscription, per-period usage vs advisory limits).
- `agentguard deploy` — CI gate (validate policies + red-team + `--fail-on`) and
  a composite GitHub Action `.github/actions/agentguard`.
- Frontend: Integrations + Billing pages.

Steps 10–13 add enterprise SSO/SCIM, multi-region, the AI security analyst, and
the TypeScript / .NET SDKs — see [`ROADMAP.md`](ROADMAP.md).
