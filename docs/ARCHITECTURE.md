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

## 7. Current state (Step 0)

Implemented: repo layout, `infra/docker-compose.yml` (all six backing services
with health checks), `apps/api` FastAPI skeleton (`/`, `/healthz`, `/readyz`,
OpenAPI), `apps/web` Next.js skeleton, CI (lint + test), this document set.

Everything else is a `README.md` placeholder describing what the directory will
hold and which step fills it in — see [`ROADMAP.md`](ROADMAP.md).
