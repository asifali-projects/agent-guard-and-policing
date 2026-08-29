# docs

## Start here

| File | Purpose |
|------|---------|
| [`MANUAL.md`](MANUAL.md) | **Full product manual** — every feature, what it does, how to use it (UI / API / SDK / CLI) |
| [`RUNNING.md`](RUNNING.md) | **How to run it** — prerequisites, quickstart, local dev, config, database ops, testing, deployment, multi-region, troubleshooting |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | **System design** — planes, request paths, datastores, tenancy, tech stack, deployment topology, per-step build log |
| [`ROADMAP.md`](ROADMAP.md) | The step-by-step implementation plan mapped to the PRD (all 15 steps 0–14 done) |
| [`DATA_MODEL.md`](DATA_MODEL.md) | The 46 Postgres tables + the ClickHouse event tables |

## Per-subsystem design docs

| File | Subsystem | Step |
|------|-----------|------|
| [`AUTH.md`](AUTH.md) | Authentication, tenancy, RBAC, API keys, audit chain | 2 |
| [`POLICY.md`](POLICY.md) | Policy engine + runtime API | 3 |
| [`RISK_DLP.md`](RISK_DLP.md) | Risk engine + data-loss prevention | 4 |
| [`SDK.md`](SDK.md) | Python / TypeScript / .NET SDKs + CLI | 5, 13 |
| [`REDTEAM.md`](REDTEAM.md) | Offensive red-team engine + findings | 6 |
| [`WEB.md`](WEB.md) | The Next.js dashboard | 7 |
| [`DETECTION.md`](DETECTION.md) | Behavioral detection, incidents, agent graph | 8 |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | Event bus, webhooks, CI/CD, billing | 9 |
| [`SSO.md`](SSO.md) | Enterprise SAML 2.0 / OIDC | 10 |
| [`SCIM.md`](SCIM.md) | SCIM 2.0 provisioning | 11 |
| [`ANALYST.md`](ANALYST.md) | AI Security Analyst | 12 |
| [`MULTI_REGION.md`](MULTI_REGION.md) | Data-residency regions | 14 |

## Decisions

[`adr/`](adr/) — Architecture Decision Records
([0001](adr/0001-python-first-backend.md) Python-first backend ·
[0002](adr/0002-multi-region-data-residency.md) multi-region by isolated
deployments).

The source of truth for product scope is
[`../agent-police-prd.docx`](../agent-police-prd.docx) (PRD v1.0). Public
end-user documentation (`docs.<product>.com`) is generated partly from the API's
OpenAPI spec and is a separate deliverable.
