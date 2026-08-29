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
| 2 | Auth + tenancy + RBAC | Email + OAuth login, JWT sessions (rotation/reuse-detection/device tracking), TOTP MFA, 7-role RBAC + 31-permission catalog, tenant-scoping deps, API-key system (§52), audit hash-chain. See [`AUTH.md`](AUTH.md) | §9, §49–52 | ☑ |
| 3 | Policy Engine + Runtime API | `packages/policy-engine` (pure, 21 tests), `POST /v1/runtime/evaluate`, hierarchy + precedence + conditions, Redis policy cache, rate limiting, approval binding, policy/approval/inventory routers. See [`POLICY.md`](POLICY.md) | §23–25, §29, §42, §46 | ☑ |
| 4 | Risk Engine + DLP | 7-factor risk engine + 15 DLP detectors (Luhn-checked cards, keys, secrets), classification → action, NEVER_EXFIL, integrated into `/v1/runtime/evaluate` (real risk score replaces the placeholder), `/v1/risk` + `/v1/data-security` routers. See [`RISK_DLP.md`](RISK_DLP.md) | §26–27 | ☑ |
| 5 | Python SDK + CLI | `agentguard` package (SDK + CLI): `@guard.tool` enforces via `/v1/runtime/evaluate` (deny/approval/redact/rate-limit + fail-safe), identity auto-register, `agentguard login/agents/policy validate/scan/logs`, `GET /v1/audit/events`. See [`SDK.md`](SDK.md) | §33, §36–38, §71 | ☑ |
| 6 | Red-Team Engine | 21-technique catalog (all 6 categories), side-effect-free `core_decision` sandbox, evaluator + upserted findings, `/v1/redteam` assessments + §22 finding actions (remediation policy, incident, retest, suppress), minimal `/v1/mcp` + heuristic scan, CLI `redteam run --fail-on` + `mcp scan`. See [`REDTEAM.md`](REDTEAM.md) | §17–22 | ☑ |
| 7 | Web dashboard | Next.js 14 + Tailwind + TanStack Query: auth, §8 sidebar, "Am I safe?" dashboard, agent inventory + detail tabs (posture breakdown), findings + §22 actions, policies + validate, approvals, red-team, audit + chain-verify, tools/MCP/data-security/API-keys/team. `GET /v1/dashboard/summary` + CORS. See [`WEB.md`](WEB.md) | §8–14, §22, §29, §33 | ☑ |
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
