# Running AgentGuard

How to stand up, develop, test, and deploy the platform. Companion to
[`MANUAL.md`](MANUAL.md) (what the product does) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (how it's built).

---

## 1. What runs where

| Component | Path | Runtime | Local port* |
|---|---|---|---|
| Control-plane + runtime API | `apps/api` | FastAPI / Python 3.11 | 8010 |
| Web dashboard | `apps/web` | Next.js 14 / Node 20+ | 3010 |
| AI Security Analyst service | `agentguard_api.analyst.asgi:app` | FastAPI (same image as API) | 8020 |
| Workers (event stream) | `apps/workers` | Python — **scaffolded**; the synchronous detection / risk / DLP paths run in-process in the API today | — |
| Policy engine | `packages/policy-engine` | pure-Python library, embedded in the API and the Python SDK | — |
| SDKs + CLI | `packages/sdk-{python,typescript,dotnet}` | library + `agentguard` CLI | — |

\* Ports assume the `.env` from [§4](#4-configuration). Without a `.env` the
Docker Compose defaults are 8000 / 3000 / 8020.

### Backing services (Docker Compose)

| Service | Image | Host port | Role |
|---|---|---|---|
| `postgres` | `pgvector/pgvector:pg16` | 5442 | source of truth |
| `redis` | `redis:7` | 6389 | cache, rate limits, session/approval state, usage counters |
| `redpanda` | Redpanda (Kafka API) | 19092 | runtime event transport |
| `clickhouse` | ClickHouse | 8124 (HTTP) | high-volume event store + analytics |
| `qdrant` | Qdrant | 6343 | threat-intel / attack-pattern vectors (never authz) |
| `minio` | MinIO | 9002 (S3) / 9003 (console) | red-team evidence, exports, large payloads |

---

## 2. Prerequisites

- **Docker** + Docker Compose v2
- **Python 3.11** (for the API / policy engine / Python SDK)
- **Node 20+** (for the web app and the TypeScript SDK)
- **.NET 8 SDK** — only if you work on `packages/sdk-dotnet`
- `make` (Unix/macOS) or PowerShell (`.\tasks.ps1`, Windows)

---

## 3. Quickstart — everything in containers

```bash
cp .env.example .env
make up            #  docker compose --profile apps up --build -d
# Windows:  .\tasks.ps1 up
```

This builds and starts the backing services, runs the one-shot `migrate`
container (`alembic upgrade head` + RBAC seed + ClickHouse schema), then starts
`api`, `ai-analyst`, and `web`.

- Dashboard: <http://localhost:3010> (or `:3000` without `.env`)
- API docs: <http://localhost:8010/docs>
- Create the first account from the dashboard's **Create account** tab.

Stop: `make down` / `.\tasks.ps1 down`. Wipe data: `make infra-clean`.

---

## 4. Configuration

Copy `.env.example` → `.env` and adjust. Every value has a working default.
Key groups (full list in `.env.example` and `apps/api/agentguard_api/config.py`):

### Core

| Var | Default | Notes |
|---|---|---|
| `AGENTGUARD_ENV` | `development` | `development` / `staging` / `production` / `test` |
| `AGENTGUARD_SECRET_KEY` | dev placeholder | **change in prod** — `openssl rand -hex 32`. Signs JWTs + state tokens |
| `AGENTGUARD_LOG_LEVEL` | `INFO` | structlog level |
| `AGENTGUARD_OPEN_REGISTRATION` | `true` | set `false` in prod once seeded |

### Datastores (each region has its own)

`DATABASE_URL`, `REDIS_URL`, `KAFKA_BOOTSTRAP_SERVERS`, `CLICKHOUSE_HOST` /
`CLICKHOUSE_PORT`, `QDRANT_URL`, `S3_ENDPOINT_URL` / `S3_ACCESS_KEY` /
`S3_SECRET_KEY` / `S3_BUCKET`.

### Auth / sessions

`AGENTGUARD_JWT_ALG` (`HS256`), `AGENTGUARD_ACCESS_TTL` (900s),
`AGENTGUARD_REFRESH_TTL` (30d), `AGENTGUARD_MFA_ISSUER`,
`AGENTGUARD_CORS_ORIGINS`, `AGENTGUARD_OAUTH_REDIRECT_BASE` (default
`http://localhost:8010`), `AGENTGUARD_WEB_BASE_URL` (default
`http://localhost:3010`).

OAuth / SSO providers are enabled only when their pair is set:
`GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_ID` /
`MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT`. Enterprise SAML/OIDC connections
are configured per-org via the API/UI, not env — see [`SSO.md`](SSO.md).

### AI Security Analyst

| Var | Default | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | when set, the analyst uses Claude; otherwise a deterministic router |
| `AGENTGUARD_ANALYST_MODEL` | `claude-sonnet-4-5` | model id for the tool-use loop |
| `AGENTGUARD_ANALYST_MAX_ITERS` | `6` | max tool round-trips |
| `AGENTGUARD_ANALYST_HOURLY_QUOTA` | `60` | questions per org per hour (0 = unlimited) |
| `AGENTGUARD_ANALYST_ENABLED` | `true` | master switch |

### Multi-region (PRD §76)

| Var | Default | Notes |
|---|---|---|
| `AGENTGUARD_REGION` | `us` | the region **this** deployment serves: `us` / `eu` / `me` / `apac` |
| `AGENTGUARD_REGIONS` | `us\|United States\|http://localhost:8010\|http://localhost:3010` | discovery map: `code\|name\|api_url\|web_url`, comma-separated |

See [§9](#9-adding-a-region) and [`MULTI_REGION.md`](MULTI_REGION.md).

---

## 5. Local development (native API + web, Dockerised infra)

```bash
cp .env.example .env

# 1. backing services only
make infra-up                         # .\tasks.ps1 infra-up

# 2. API: venv + editable installs (policy-engine, sdk-python, api[dev])
make api-install                      # .\tasks.ps1 api-install

# 3. database
make db-migrate                       # alembic upgrade head
make db-seed                          # RBAC catalog + billing plans (idempotent)
make events-migrate                   # ClickHouse event tables

# 4. run the API (reload)
make api-dev                          # uvicorn ... --reload --port 8010

# 5. web (separate terminal)
make web-install
make web-dev                          # next dev, :3010
```

The AI-analyst service is optional locally — the API already serves
`/v1/analyst/*`. To run it standalone:
`uvicorn agentguard_api.analyst.asgi:app --port 8020` from `apps/api`.

---

## 6. Database operations

All via the API venv (`apps/api/.venv`), from `apps/api`:

| Task | Make | Command |
|---|---|---|
| Apply migrations | `make db-migrate` | `alembic upgrade head` |
| New migration | — | `alembic revision --autogenerate -m "…"` (`.\tasks.ps1 db-revision "…"`) |
| Check model drift | `make db-check` | `alembic check` — must print *"No new upgrade operations detected"* |
| Roll back one | `make db-downgrade` | `alembic downgrade -1` |
| Seed RBAC + plans | `make db-seed` | `python -m agentguard_api.rbac.seed` |
| ClickHouse schema | `make events-migrate` | `python -m agentguard_api.events.migrate` |

Migrations to date: `0001` initial · `0002` auth · `0003` tz-aware datetimes ·
`0004` behavior_profiles · `0005` sso_connections · `0006` scim ·
`0007` analyst_conversations · `0008` org region enum.

---

## 7. Testing

| Suite | Where | Command |
|---|---|---|
| API (needs Postgres + Redis) | `apps/api` | `make api-test` / `pytest -q` — 102 tests |
| Policy engine | `packages/policy-engine` | `pytest -q` — 21 tests |
| Python SDK | `packages/sdk-python` | `pytest -q` — 13 tests |
| TypeScript SDK | `packages/sdk-typescript` | `npm test` — 22 tests (`node:test` via `tsx`) |
| .NET SDK | `packages/sdk-dotnet` | `dotnet test tests/AgentGuard.Tests/AgentGuard.Tests.csproj` — 15 tests |
| Web | `apps/web` | `npm run typecheck && npm run build` |

Lint/format for Python: `make api-lint` (ruff check + format check). The API test
DB is a throwaway database created and migrated per session by
`tests/conftest.py`.

---

## 8. Continuous integration

`.github/workflows/ci.yml` runs on every PR: `policy-engine`, `sdk-python`,
`sdk-typescript`, `sdk-dotnet`, `api` (with Postgres + Redis services,
`alembic check`, seed, pytest), `web` (typecheck + build), and `compose`
(`docker compose config -q`).

---

## 9. Adding a region

A region is a **complete, isolated stack** — its own Postgres, Redis,
ClickHouse, Redpanda, MinIO, and `AGENTGUARD_SECRET_KEY`.

1. Provision fresh infrastructure for, say, `eu`.
2. Deploy `apps/api` + `apps/web` + `ai-analyst` pointing at it, with:
   - `AGENTGUARD_REGION=eu`
   - `AGENTGUARD_REGIONS="us|United States|https://us.api…|https://us.app…, eu|European Union|https://eu.api…|https://eu.app…"` (list **all** regions, same value everywhere)
   - `DATABASE_URL`, `REDIS_URL`, `S3_*`, … pointed at the EU infra
3. `alembic upgrade head` + `python -m agentguard_api.rbac.seed` +
   `python -m agentguard_api.events.migrate` against the EU database.
4. Point DNS: `eu.api.agentguard.example`, `eu.app.agentguard.example`.

That's it — no application code changes. `GET /v1/regions` now advertises both;
the dashboard sign-up shows a region picker; an org created in the EU deployment
is pinned to `eu` forever. A request to the EU API for a US-homed org returns
`421 Misdirected Request` with the US URL in `X-AgentGuard-Region-Url`.

---

## 10. Production notes

- **Secrets**: generate a unique `AGENTGUARD_SECRET_KEY` per region; store DB /
  S3 / IdP credentials in your secret manager, not `.env`.
- **Registration**: set `AGENTGUARD_OPEN_REGISTRATION=false` after bootstrapping.
- **TLS / gateway**: terminate TLS at the edge; set `AGENTGUARD_CORS_ORIGINS`,
  `AGENTGUARD_OAUTH_REDIRECT_BASE`, `AGENTGUARD_WEB_BASE_URL` to the public URLs.
- **Images**: `apps/api/Dockerfile` builds the API; the `ai-analyst` service
  reuses it with a different entrypoint. `apps/web/Dockerfile` builds the web app.
- **Scaling**: the API is stateless (sessions + rate limits live in Redis);
  scale horizontally. The runtime critical path targets p95 < 50 ms and makes no
  LLM call.
- **DR** (PRD §77): automated Postgres backups + PITR, replicated event storage,
  tested restores. Target RPO < 15 min, RTO < 1 h.
- **Observability**: structlog JSON logs; OpenTelemetry is the intended tracing
  layer (PRD §57).

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `pytest` skips with "Postgres not reachable" | `make infra-up` first; check `DATABASE_URL` port matches `POSTGRES_PORT` |
| `alembic check` reports operations | models drifted — generate a migration or revert the model change |
| API 401 on every call | expired/'missing token; the web app auto-refreshes, SDKs need a valid `ag_*` key |
| API 421 `Misdirected Request` | the org is homed in another region — use the URL in the `X-AgentGuard-Region-Url` header |
| Analyst answers say "engine: fallback" | no `ANTHROPIC_API_KEY` set (this is fine — deterministic mode) |
| Web can't reach API | `NEXT_PUBLIC_API_BASE_URL` / `AGENTGUARD_CORS_ORIGINS` mismatch |
| Port conflicts on start | the `*_PORT` block in `.env` is deliberately off common defaults; adjust further if needed |
