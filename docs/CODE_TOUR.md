# Code Tour — how to start analysing AgentGuard

A guided reading order for someone reviewing this codebase for the first time.
Budget ~2–3 hours for the fast path, a day for the deep pass.

---

## 0. Orient (15 min)

| Read | Why |
|---|---|
| [`README.md`](../README.md) | repo layout, what's where, status |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) §1–6 | planes, request paths, datastores, tenancy, tech stack |
| [`docs/ROADMAP.md`](ROADMAP.md) | the 15-step build, each mapped to a PRD section and a design doc |
| [`docs/MANUAL.md`](MANUAL.md) §1–3 | the product in plain terms + core concepts |

Then skim the **PRD** ([`agent-police-prd.docx`](../agent-police-prd.docx)) —
the source of truth for scope. Sections referenced most: §6 (planes), §23–25
(policy + runtime), §24 (decisions), §42 (runtime API), §44 (data model).

---

## 1. Run it (20 min)

Follow [`docs/RUNNING.md`](RUNNING.md) §5 (local dev). Then:

```bash
open http://localhost:8010/docs      # every endpoint, live
open http://localhost:3010           # the dashboard — create an account
```

Click through the dashboard once. Watch the **Audit Log** fill as you act.

---

## 2. The critical path (45 min) — this is the heart of the product

Read in this order:

1. **`packages/policy-engine/`** — pure, no I/O. Start at
   `src/agentguard_policy/__init__.py` → `evaluate.py`. This is *what the policy
   says*. Tests: `packages/policy-engine/tests/` (21). Doc: [`POLICY.md`](POLICY.md).
2. **`apps/api/agentguard_api/runtime/core.py`** — `core_decision()`: the
   side-effect-free pipeline `DLP → policy → risk → combine`. No writes.
3. **`apps/api/agentguard_api/runtime/service.py`** — `evaluate_runtime()`:
   wraps `core_decision` with the stateful steps (rate-limit consume, approval
   binding, event emit, audit, usage meter).
4. **`apps/api/agentguard_api/runtime/router.py`** — `POST /v1/runtime/evaluate`.
5. **`apps/api/agentguard_api/risk/engine.py`** — the 7-factor score.
6. **`apps/api/agentguard_api/dlp/detectors.py`** — the 15 regex detectors +
   Luhn + `NEVER_EXFIL`.

Tests to read alongside: `apps/api/tests/test_runtime.py`,
`test_risk_dlp_runtime.py`.

---

## 3. The spine — auth, tenancy, the Principal (30 min)

1. **`agentguard_api/auth/dependencies.py`** — `get_principal()` resolves every
   request to a `Principal` (user-JWT or API-key), attaches the org + permission
   set, and runs the **residency guard** (`421` for out-of-region orgs).
   `require_permission(...)` is the endpoint gate.
2. **`agentguard_api/rbac/catalog.py`** — the 32-permission catalog + the 7
   built-in role grants (the source of truth).
3. **`agentguard_api/auth/service.py`** — register / authenticate / session
   rotation + reuse detection.
4. **`agentguard_api/audit_log.py`** — the append-only per-org SHA-256 hash
   chain (`record()` + `verify_chain()`).

Doc: [`AUTH.md`](AUTH.md). Tests: `test_auth.py`, `test_rbac_apikeys.py`,
`test_audit.py`.

---

## 4. The data model (20 min)

- [`docs/DATA_MODEL.md`](DATA_MODEL.md) — the 46 tables by domain.
- `agentguard_api/models/base.py` — `enum_column` (VARCHAR-backed enums),
  `org_column`, the mixins, the naming convention.
- `agentguard_api/models/__init__.py` — the full registry; each `*.py` is one
  domain.
- `apps/api/migrations/versions/` — 8 migrations, `0001` is the big one.

---

## 5. The rest of the platform (pick by interest)

Each subsystem = a package under `agentguard_api/`, a router, a design doc, and
a test file:

| Subsystem | Package | Doc | Tests |
|---|---|---|---|
| Red-team engine | `redteam/` | [`REDTEAM.md`](REDTEAM.md) | `test_redteam.py` |
| Detection / incidents / graph | `detection/`, `incidents/`, `graph/` | [`DETECTION.md`](DETECTION.md) | `test_incidents_graph.py` |
| Integrations / webhooks / billing | `events/`, `integrations/`, `billing/` | [`INTEGRATIONS.md`](INTEGRATIONS.md) | `test_integrations_billing.py` |
| Enterprise SSO | `sso/` | [`SSO.md`](SSO.md) | `test_sso.py` |
| SCIM | `scim/` | [`SCIM.md`](SCIM.md) | `test_scim.py` |
| AI analyst | `analyst/` | [`ANALYST.md`](ANALYST.md) | `test_analyst.py` |
| Multi-region | `regions.py` | [`MULTI_REGION.md`](MULTI_REGION.md) | `test_multi_region.py` |

---

## 6. Clients (20 min)

- **`packages/sdk-python/agentguard/`** — the reference SDK. `guard.py`
  (`@guard.tool`, `check()`), `client.py`, `decision.py`, `cli/`.
- `packages/sdk-typescript/src/` and `packages/sdk-dotnet/src/AgentGuard/`
  mirror it exactly. Doc: [`SDK.md`](SDK.md).

---

## 7. The dashboard (15 min)

`apps/web/` — Next.js 14 App Router. `lib/api.ts` (fetch + token refresh +
`421` handling), `lib/auth.tsx` (AuthProvider), `components/Sidebar.tsx` (the
PRD §8 IA), `app/(app)/*/page.tsx` (one per feature). Doc: [`WEB.md`](WEB.md).

---

## What to look for when reviewing

- **Determinism on the hot path** — grep the runtime path for any network / LLM
  call. There should be none.
- **`organization_id` everywhere** — every query is tenant-scoped; the
  `Principal` binds it, never the client.
- **Fail-safe** — `fail_mode` handling in the SDKs (`guard.py`) and the runtime.
- **Data minimisation** — audit + event rows store hashes, not payloads.
- **The residency guard** — `regions.assert_servable` is called in exactly one
  hot place (`get_principal`) plus at creation.
- **Tests as spec** — each `test_*.py` reads as the behavioural contract for its
  subsystem.

## Verifying it's healthy

```bash
cd apps/api && make api-lint && make db-check && make api-test   # ruff + alembic + 102 tests
cd packages/policy-engine && pytest -q                           # 21
cd packages/sdk-python && pytest -q                              # 13
cd packages/sdk-typescript && npm test                          # 22
cd packages/sdk-dotnet && dotnet test tests/AgentGuard.Tests/AgentGuard.Tests.csproj  # 15
cd apps/web && npm run typecheck && npm run build
docker compose -f infra/docker-compose.yml config -q
```
