# AgentGuard

> **Working product name.** "AgentGuard" is a placeholder — an existing product
> uses this name. Naming / trademark / domain validation is required before any
> public launch. See [`agent-police-prd.docx`](agent-police-prd.docx) for the
> full Product Requirements Document.

**A security control plane for the agentic workforce.**

AgentGuard discovers autonomous AI agents, continuously red-teams their
behavior, governs identities and permissions, evaluates every high-impact
action, protects sensitive data, enforces runtime policies, and provides
enterprise-grade monitoring and incident response.

The core product principle:

> The AI model decides what it *wants* to do. AgentGuard decides whether it is
> *allowed* to do it.

The product loop:

```
DISCOVER → ASSESS → RED-TEAM → GOVERN → PROTECT → MONITOR → RESPOND → (RED-TEAM AGAIN)
```

---

## Repository layout

This is a monorepo. Each top-level directory is built out over a sequence of
implementation steps (see [`docs/ROADMAP.md`](docs/ROADMAP.md)).

```
agent-guard/
├── apps/
│   ├── api/           FastAPI control-plane + runtime API (Python)
│   ├── workers/       Async workers: event processing, scheduled scans (Python)
│   └── web/           Next.js dashboard (TypeScript / React)
├── packages/
│   ├── policy-engine/ Deterministic policy evaluation library (Python)
│   ├── sdk-python/    agentguard — Python SDK
│   ├── sdk-typescript/ @agentguard/sdk — TypeScript SDK
│   ├── sdk-dotnet/    AgentGuard.NET — .NET SDK
│   └── cli/           agentguard — developer CLI (Python)
├── services/
│   ├── red-team/      Offensive security engine: attack planner → evaluator → findings
│   ├── risk-engine/   Multi-factor risk scoring
│   ├── detection/     Behavioral baseline + anomaly detection
│   └── ai-analyst/    Natural-language security analyst (read-only by default)
├── infra/
│   ├── docker-compose.yml   Local backing services (Postgres, Redis, Redpanda, ClickHouse, Qdrant, MinIO)
│   └── k8s/                 Kubernetes manifests (production)
└── docs/               Architecture, ADRs, roadmap
```

### Data stores (all containerised for local dev)

| Store       | Image        | Purpose                                                             |
|-------------|--------------|--------------------------------------------------------------------|
| PostgreSQL  | `postgres:16`| Core transactional data — orgs, agents, tools, policies, findings  |
| Redis       | `redis:7`    | Policy cache, rate limiting, session + approval state              |
| Redpanda    | `redpanda`   | Event stream (Kafka API) for runtime events                        |
| ClickHouse  | `clickhouse` | High-volume runtime events, tool calls, analytics                  |
| Qdrant      | `qdrant`     | Threat-intel / attack-pattern vectors (never used for authz)       |
| MinIO       | `minio`      | S3-compatible object storage — red-team evidence, reports, exports |

Application code also ships as container images (`Dockerfile` per app), but for
local development you can run the API and web app natively for fast reload.

---

## Quick start

Prerequisites: Docker + Docker Compose, Python 3.11+, Node 20+.

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Start backing services (Postgres, Redis, Redpanda, ClickHouse, Qdrant, MinIO)
make infra-up

# 3. Install + run the API (native, with reload)
make api-install
make api-dev            # http://localhost:8000  — /healthz, /docs

# 4. Install + run the web dashboard
make web-install
make web-dev            # http://localhost:3000
```

To run everything (including the API and web) in containers instead:

```bash
make up                 # docker compose up --build
```

Tear down:

```bash
make down               # stop app containers
make infra-down         # stop backing services (add `make infra-clean` to wipe volumes)
```

---

## Status

**Step 0 — Repo + infra scaffold.** In place:

- Monorepo directory structure
- `infra/docker-compose.yml` with all six backing services + health checks
- FastAPI `apps/api` skeleton: config, `/healthz`, `/readyz` (checks Postgres +
  Redis), OpenAPI docs, one passing test
- Next.js `apps/web` skeleton
- `Makefile` with common tasks
- GitHub Actions CI skeleton (lint + test)
- `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, first ADR

Not yet implemented (later steps): database schema + migrations, auth, policy
engine, runtime evaluation, risk engine, DLP, SDKs, red-team engine, dashboard
features, integrations, billing. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## License

Intended split (PRD §68): SDKs, CLI, policy-engine, basic scanner and security
rules under a permissive open-source license; control plane, advanced red-team,
analytics, and enterprise features commercial. License files are added when that
split is formalised.
