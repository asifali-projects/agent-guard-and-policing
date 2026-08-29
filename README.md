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
│   ├── sdk-python/    agentguard — Python SDK + CLI
│   ├── sdk-typescript/ @agentguard/sdk — TypeScript SDK + CLI
│   ├── sdk-dotnet/    AgentGuard.NET — .NET SDK + CLI
│   └── cli/           reserved for a future standalone CLI distribution
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
make api-dev            # http://localhost:8010  — /healthz, /docs

# 4. Install + run the web dashboard
make web-install
make web-dev            # http://localhost:3010
```

> Windows: use `.\tasks.ps1 <task>` (same task names) instead of `make`.

Host ports use an AgentGuard-specific block (Postgres `5442`, Redis `6389`,
Redpanda `19092`, ClickHouse `8124`, Qdrant `6343`, MinIO `9002`/`9003`,
API `8010`, web `3010`) so the stack runs alongside other local instances.
Override any in `.env`.

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

**All 14 implementation steps (0–13) are complete.** See
[`docs/ROADMAP.md`](docs/ROADMAP.md) for the per-step breakdown.

- **Control plane + runtime** (`apps/api`) — auth/tenancy/RBAC, the deterministic
  policy engine + `POST /v1/runtime/evaluate`, the 7-factor risk engine + DLP,
  red-team engine, behavioral detection, incidents, agent graph, integrations +
  webhooks, billing/metering, enterprise SSO (SAML/OIDC), SCIM 2.0, and the AI
  Security Analyst.
- **Dashboard** (`apps/web`) — Next.js 14, the full PRD §8 information
  architecture.
- **SDKs + CLI** — Python (`agentguard`), TypeScript (`@agentguard/sdk`), and
  .NET (`AgentGuard.NET`), all behaviourally identical.
- **Docs** — one design doc per subsystem under [`docs/`](docs), plus ADRs.

Per-subsystem docs: [`AUTH`](docs/AUTH.md) · [`POLICY`](docs/POLICY.md) ·
[`RISK_DLP`](docs/RISK_DLP.md) · [`SDK`](docs/SDK.md) · [`REDTEAM`](docs/REDTEAM.md) ·
[`WEB`](docs/WEB.md) · [`DETECTION`](docs/DETECTION.md) ·
[`INTEGRATIONS`](docs/INTEGRATIONS.md) · [`SSO`](docs/SSO.md) ·
[`SCIM`](docs/SCIM.md) · [`ANALYST`](docs/ANALYST.md).

---

## License

Intended split (PRD §68): SDKs, CLI, policy-engine, basic scanner and security
rules under a permissive open-source license; control plane, advanced red-team,
analytics, and enterprise features commercial. License files are added when that
split is formalised.
