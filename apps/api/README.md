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
└── routers/
    └── health.py   /healthz, /readyz
```

## Roadmap inside this package

| Step | Adds |
|------|------|
| 1 | SQLAlchemy models + Alembic migrations (PRD §44) |
| 2 | Auth (OAuth/OIDC/SAML), org/tenant scoping, RBAC, API keys |
| 3 | `POST /v1/runtime/evaluate`, policy hierarchy, decision engine |
| 4 | Risk engine + DLP hooks |
| 6 | Red-team assessment + findings endpoints |
| 9 | Integrations, webhooks, billing/usage endpoints |
