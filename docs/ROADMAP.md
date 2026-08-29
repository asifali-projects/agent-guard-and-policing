# Implementation Roadmap

The PRD ([`../agent-police-prd.docx`](../agent-police-prd.docx)) describes the
full target product. It is deliberately **not** MVP-scoped. Execution is
sequenced into 14 steps. Steps 0–9 bring the product end-to-end; 10–13 add
enterprise features on top.

Legend: ☐ not started · ◐ in progress · ☑ done

| Step | Name | Key deliverables | PRD | State |
|------|------|------------------|-----|-------|
| 0 | Repo + infra scaffold | Monorepo layout, `docker-compose` (Postgres, Redis, Redpanda, ClickHouse, Qdrant, MinIO), FastAPI skeleton with health probes, Next.js skeleton, CI, docs | §53–56 | ☑ |
| 1 | Data model + migrations | 36 SQLAlchemy models + Alembic initial migration for all Postgres tables; 5 ClickHouse event tables + bootstrap. See [`DATA_MODEL.md`](DATA_MODEL.md) | §44–45 | ☑ |
| 2 | Auth + tenancy + RBAC | Email/OAuth login, org isolation, 7 roles, API-key system, sessions, MFA stubs | §49–52 | ☐ |
| 3 | Policy Engine + Runtime API | `packages/policy-engine`, `POST /v1/runtime/evaluate`, policy hierarchy, decision engine, Redis cache | §23–25, §42 | ☐ |
| 4 | Risk Engine + DLP | `services/risk-engine` (7 factors), data classifiers (PII/secrets/keys), redact/block | §26–27 | ☐ |
| 5 | Python SDK + CLI | `pip install agentguard`, `guard.protect()`, `@guard.tool`, `agentguard` CLI | §36–38, §71 | ☐ |
| 6 | Red-Team Engine | `services/red-team` pipeline, attack categories, assessment API, CI-triggered re-tests | §18–22 | ☐ |
| 7 | Web dashboard | Next.js IA (§8), dashboard, agent inventory/detail, findings, policies, approvals, audit | §8–14, §22, §29 | ☐ |
| 8 | Detection + Incidents + Graph | Behavioral baseline/anomaly, incident lifecycle, agent graph / blast radius, audit export | §28, §30–33 | ☐ |
| 9 | Integrations + CI/CD + Billing | GitHub Action, Slack/SIEM webhooks, Stripe metering + usage records | §60–65 | ☐ |
| 10 | Enterprise SSO | SAML / OIDC identity federation | §9, §51 | ☐ |
| 11 | SCIM provisioning | Automated user lifecycle from customer IdP | §51 | ☐ |
| 12 | AI Security Analyst | `services/ai-analyst` — read-only natural-language Q&A | §35 | ☐ |
| 13 | TypeScript + .NET SDKs | `@agentguard/sdk`, `AgentGuard.NET` | §37, §39–40 | ☐ |

## Mapping to PRD engineering phases (§87)

- **Phase A — Foundation:** Steps 0–3
- **Phase B — Security Core:** Steps 3–4 (runtime guard, risk, DLP, approval, audit)
- **Phase C — Offensive Security:** Step 6
- **Phase D — Platform:** Steps 7–9 (dashboard, graph, analytics, incidents, integrations)
- **Phase E — Enterprise:** Steps 10–11
- **Phase F — Intelligence:** Steps 8, 12

## Explicitly deferred (PRD §88)

Custom SIEM/IAM/DLP engines, 20+ framework integrations, full on-prem
distribution, autonomous AI remediation. AgentGuard **integrates**, it does not
reinvent the security industry.
