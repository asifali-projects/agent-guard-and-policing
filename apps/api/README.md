# apps/api

AgentGuard control-plane + runtime API. FastAPI, async SQLAlchemy, Python 3.11.

## Run locally

```powershell
# from the repo root
.\tasks.ps1 api-install
.\tasks.ps1 api-dev
```

- API: <http://localhost:8010>
- Interactive docs: <http://localhost:8010/docs>
- Liveness: `GET /healthz` · Readiness: `GET /readyz`

## Test

```powershell
.\tasks.ps1 api-test
```

## Layout

```
agentguard_api/
├── main.py         FastAPI app + lifespan
├── config.py       Settings (env / .env)
├── logging.py      Structured JSON logging
├── db.py           Async engine + ping()
├── cache.py        Redis client + ping()
├── models/         SQLAlchemy 2.0 models (PRD §44) — one module per domain
├── events/         ClickHouse event-store schema + bootstrap (PRD §45)
├── security/       Password/JWT/API-key/TOTP primitives (no DB, no FastAPI)
├── auth/           Sessions, principals, OAuth, /v1/auth router (PRD §9, §51)
├── rbac/           Permission catalog + role grants + seed (PRD §50)
├── organizations/  /v1/organizations + members router
├── apikeys/        /v1/organizations/{id}/api-keys router (PRD §52)
├── inventory/      /v1/agents + /v1/tools (minimal; rich views in Step 7)
├── policies/       /v1/policies CRUD + bindings + validate + simulate (PRD §23)
├── approvals/      /v1/approvals — list / approve / reject (PRD §29)
├── dlp/            Pure detectors + classification + action resolution (PRD §27)
├── risk/           7-factor risk engine + /v1/risk router (PRD §26)
├── data_security/  /v1/data-security — scan, classifications, data policies
├── runtime/        POST /v1/runtime/evaluate — DLP + policy + risk (PRD §24–27, §42)
├── audit/          /v1/audit/events + /v1/audit/verify (PRD §33)
├── audit_log.py    Append-only hash-chained audit writer (PRD §33)
└── routers/
    └── health.py   /healthz, /readyz
migrations/         Alembic (async) — versions/
```

The deterministic policy engine lives in the monorepo package
[`packages/policy-engine`](../../packages/policy-engine) and is installed
editable (`tasks.ps1 api-install`).

## Database

```powershell
# from the repo root, with infra running
.\tasks.ps1 db-migrate         # alembic upgrade head
.\tasks.ps1 db-seed            # RBAC catalog + plans (idempotent)
.\tasks.ps1 events-migrate      # ClickHouse event tables
.\tasks.ps1 db-check            # fail if models drifted from migrations
```

See [`../../docs/DATA_MODEL.md`](../../docs/DATA_MODEL.md) and
[`../../docs/AUTH.md`](../../docs/AUTH.md).

## Roadmap inside this package

| Step | Adds |
|------|------|
| 6 | Red-team assessment + findings endpoints |
| 8 | Real behavioral baselines, incidents, agent graph |
| 9 | Integrations, webhooks, billing/usage endpoints |
