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

## 7. Current state (through Step 4)

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

Everything past Step 4 is still a `README.md` placeholder — see
[`ROADMAP.md`](ROADMAP.md).
