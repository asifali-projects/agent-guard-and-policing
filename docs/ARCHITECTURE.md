# Architecture

The system design of AgentGuard: planes, request paths, datastores, tenancy,
tech stack, and a per-step build log. All 15 steps (0–14) are implemented.

**See also:** [`MANUAL.md`](MANUAL.md) — what every feature does and how to use
it · [`RUNNING.md`](RUNNING.md) — setup, configuration, deployment ·
[`DATA_MODEL.md`](DATA_MODEL.md) — the 46 Postgres tables · [`adr/`](adr/) —
decision records.

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
Security Analyst, Developer, Auditor, Billing Admin (7 roles over a
32-permission catalog — see [`MANUAL.md` §23](MANUAL.md#23-permission-reference)).

**Data residency (PRD §76):** each organization is pinned to one region
(`us` / `eu` / `me` / `apac`) at creation. A region is a *fully isolated
deployment* — see [§8](#8-deployment-topology) and
[ADR 0002](adr/0002-multi-region-data-residency.md).

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

## 7. Current state (all 14 steps complete)

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

**Step 10** — enterprise SSO ([`SSO.md`](SSO.md)):

- `sso/` — generic OIDC (discovery + JWKS `id_token` verification) and SAML 2.0
  (`signxml` signed-assertion verification, no libxmlsec), the `sso_connections`
  model, domain-based discovery, IdP redirect / OIDC callback / SAML ACS, and
  JIT user provisioning (`external_identities` `provider="sso:<cid>"` + membership
  at the connection's `default_role`).
- `/v1/auth/sso/*` sign-in flow ends by handing the browser a session in the URL
  fragment; `/v1/organizations/{id}/sso` is `org.manage` CRUD + SP metadata.
- `auth.service.authenticate` blocks password login for domains on an `enforced`
  connection.
- Frontend: login "Single sign-on" button, `/sso/callback`, Administration → SSO.

**Step 11** — SCIM provisioning ([`SCIM.md`](SCIM.md)):

- `scim/` — SCIM 2.0 `/scim/v2` Users + Groups (RFC 7643/7644), per-org bearer
  token (`scim_configs`), `eq` filtering, PatchOp, RFC 7644 error schema via an
  app-level `ScimError` handler.
- `scim.service.sync_membership` is the bridge: it creates / re-roles / deletes
  the real `memberships` row as the IdP toggles `active` and regroups the user;
  `active:false` also revokes that org's sessions. Group display names that
  resolve to a role drive the effective role (most privileged wins; never
  `owner`).
- `/v1/organizations/{id}/scim` (`org.manage`) — enable, default role, token
  rotation; surfaced in the **SSO & SCIM** UI panel.

**Step 12** — AI Security Analyst ([`ANALYST.md`](ANALYST.md)):

- `analyst/tools.py` — 9 deterministic, org-scoped read-only queries (overview,
  agents, findings, incidents, threats, audit search, decision explain). `org_id`
  is bound from the principal, never the model.
- `analyst/engine.py` — a Claude tool-use loop when `ANTHROPIC_API_KEY` is set;
  `analyst/fallback.py` (a regex intent router) otherwise and on any model
  failure, so the feature never depends on network.
- `/v1/analyst` (`analyst.query`) — ask + persisted conversations
  (`analyst_conversations` / `analyst_messages`), per-org hourly quota in Redis,
  every query audited with its engine + tool names.
- `analyst/asgi.py` + the `ai-analyst` compose service run it as an independent
  container off the same image. Chat UI at `/analyst`.

**Step 13** — TypeScript + .NET SDKs ([`SDK.md`](SDK.md)):

- `packages/sdk-typescript` (`@agentguard/sdk`) — zero-dependency ESM, built-in
  `fetch`, `node:test`. `guard.tool(fn)` wraps an async tool that takes a single
  named-parameter object.
- `packages/sdk-dotnet` (`AgentGuard.NET`) — `net8.0`, `HttpClient` +
  `System.Text.Json`, xunit. `guard.GuardAsync(tool, params, invoke)` plus a
  `services.AddAgentGuard(...)` DI helper.
- Both mirror the Python SDK's contract exactly — identity resolution, the five
  decisions, path-based redaction, `fail_mode` closed/open, and an identical
  `agentguard` CLI (`login`, `agents list`, `policy validate`, `scan`, `logs`,
  `redteam run`, `mcp scan`, `deploy`). New CI jobs `sdk-typescript` and
  `sdk-dotnet`.

**Step 14** — multi-region data residency ([`MULTI_REGION.md`](MULTI_REGION.md),
[ADR 0002](adr/0002-multi-region-data-residency.md)):

- **One deployment = one region** (`AGENTGUARD_REGION` ∈ `us`/`eu`/`me`/`apac`).
  No cross-region database or global router — each region is a complete isolated
  stack.
- `Organization.region` is a `Region` enum, set at creation and immutable
  (migration `89d72fc74981`).
- `regions.assert_servable()` → `421 Misdirected Request` (with the correct
  regional URL in `X-AgentGuard-Region*` headers) for any org not homed here —
  enforced in `get_principal` and at `register` / org creation.
- Public `GET /v1/regions` discovery; `/v1/auth/me` exposes `region` +
  `active_region`; dashboard has a sign-up region picker, a region badge, and
  turns a 421 into a "continue in the right region" link.

All steps (0–14) are complete.

## 8. Deployment topology

```
        ┌─────────────────────────  REGION: us  ─────────────────────────┐
 DNS →  │  edge / TLS                                                     │
        │      │                                                          │
        │   apps/web (Next.js)  ── NEXT_PUBLIC_API_BASE_URL ──►  apps/api │
        │   ai-analyst  ────────────────────────────────────────►  (FastAPI, stateless, scale-out)
        │      │                                                     │    │
        │   Postgres   Redis   Redpanda   ClickHouse   Qdrant   MinIO     │
        └────────────────────────────────────────────────────────────────┘
        ┌─────────────────────────  REGION: eu  ─────────────────────────┐
        │  identical, separate infrastructure, own AGENTGUARD_SECRET_KEY  │
        └────────────────────────────────────────────────────────────────┘
```

- **One deployment = one region** (`AGENTGUARD_REGION`). No cross-region
  database, no global router in the app tier. `GET /v1/regions` is the only
  cross-region knowledge (a static discovery map, `AGENTGUARD_REGIONS`).
- **`apps/api`** is stateless — sessions, rate-limit counters, usage counters,
  and the policy cache live in Redis. Scale horizontally behind the gateway.
- **`ai-analyst`** is the same image as `apps/api` with a different entrypoint
  (`agentguard_api.analyst.asgi:app`); deploy and scale it independently.
- **`apps/workers`** (`apps/workers/`) is scaffolded for the event-stream tier
  (ClickHouse-backed baselines, campaign detection); the synchronous
  detection / risk / DLP paths run in-process in the API today.
- **Local dev** collapses this to `infra/docker-compose.yml` — one of every
  backing service plus `api`, `ai-analyst`, `web` under the `apps` profile.
  See [`RUNNING.md`](RUNNING.md).

## 9. Cross-cutting concerns

| Concern | How |
|---|---|
| **Determinism on the hot path** | `POST /v1/runtime/evaluate` makes no LLM call; policy set is Redis-cached; target p95 < 50 ms. |
| **Fail-safe** | per-agent `fail_mode` (open / closed / safe-by-tool); the SDK applies it when the API is unreachable. |
| **Data minimisation** | audit + events store hashes + metadata + classification + risk + decision, not raw prompts/payloads (PRD §75). |
| **Tamper evidence** | the audit log is an append-only per-org SHA-256 hash chain, serialised by a Postgres advisory lock; `GET /v1/audit/verify` recomputes it. |
| **Tenant isolation** | every query filters on `organization_id`; the `Principal` binds the org, endpoints double-check path vs. token. |
| **Residency isolation** | `regions.assert_servable()` → `421` for any org not homed in this deployment's region. |
| **Secrets** | Argon2id for passwords + API-key secrets; HS256 JWTs; opaque hashed refresh tokens; MFA/SSO/SCIM secrets flagged for encryption at rest (PRD §75). |
| **Logging** | structlog JSON; OpenTelemetry is the intended tracing layer (PRD §57). |
| **Best-effort side-channels** | event-bus delivery and usage metering swallow all errors — they never break a runtime decision. |
