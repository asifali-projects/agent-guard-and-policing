# Data Model (Step 1)

Source of truth: `apps/api/agentguard_api/models/` (SQLAlchemy 2.0). The initial
Alembic migration is generated from these models; `alembic check` fails CI if
they drift.

## Conventions

- **Primary keys** — UUID v4, generated application-side.
- **Timestamps** — `created_at` / `updated_at` (`TimestampMixin`), server
  defaults `now()`.
- **Tenancy** — aggregate-root tables carry `organization_id` (FK, indexed,
  `ON DELETE CASCADE`). Child tables (versions, join tables, event rows) inherit
  tenancy through their parent FK. PRD §49.
- **Enums** — stored as `VARCHAR` (`native_enum=False`). Values are checked;
  adding one is a code change, not a Postgres migration. Defined in
  `models/enums.py`.
- **Constraint names** — deterministic (`pk_`, `fk_`, `uq_`, `ix_`, `ck_`
  prefixes) so autogenerate diffs are stable.
- **Data minimisation** (PRD §75) — models store hashes + metadata + risk +
  decision, not raw prompts or tool payloads.

## Postgres tables (PRD §44)

| Domain | Module | Tables |
|--------|--------|--------|
| Tenancy / IAM | `organization.py` | `organizations`, `users`, `memberships`, `roles`, `permissions`, `role_permissions`, `service_accounts`, `api_keys` |
| Agents | `agent.py` | `agents`, `agent_versions`, `agent_identities` |
| Tools | `tool.py` | `tools`, `tool_versions`, `agent_tools` |
| MCP | `mcp.py` | `mcp_servers`, `mcp_tools` |
| Policy | `policy.py` | `policies`, `policy_versions`, `policy_bindings` |
| Red team | `redteam.py` | `redteam_assessments`, `redteam_tests`, `redteam_findings` |
| Threats / IR | `incident.py` | `threats`, `incidents`, `incident_events` |
| Approvals | `approval.py` | `approval_requests`, `approval_decisions` |
| Data security | `data_security.py` | `data_classifications`, `data_policies` |
| Integrations | `integration.py` | `integrations`, `webhooks` |
| Billing | `billing.py` | `plans`, `subscriptions`, `usage_records`, `invoices` |
| Audit | `audit.py` | `audit_events` (append-only, hash-chained) |
| Auth (Step 2) | `auth.py` | `sessions`, `external_identities` |
| Detection (Step 8) | `detection.py` | `behavior_profiles` (per-agent baseline) |
| Enterprise SSO (Step 10) | `sso.py` | `sso_connections` (per-org SAML/OIDC IdP) |
| SCIM (Step 11) | `scim.py` | `scim_configs`, `scim_users`, `scim_groups`, `scim_group_members` |
| AI Analyst (Step 12) | `analyst.py` | `analyst_conversations`, `analyst_messages` |

46 tables. Migrations: `0001` initial · `0002` auth · `0003` tz-aware datetimes ·
`0004` behavior_profiles · `0005` sso_connections · `0006` scim ·
`0007` analyst_conversations.

### Notable relationships

- `agents.current_version_id → agent_versions.id` is a deferred FK
  (`use_alter`), created after both tables exist — see the initial migration.
- `agent_identities` is 1:1 with `agents`; `identity` (e.g. `agent:finance-prod`)
  is globally unique (PRD §15).
- `policy_bindings` attaches a policy at one level of the hierarchy
  org → env → agent → tool → action (PRD §23).
- `approval_requests.request_id` and `audit_events.trace_id` / `request_id`
  correlate a runtime decision across stores (PRD §43).

## ClickHouse event store (PRD §45)

Database `agentguard_events`, `MergeTree`, monthly partitions, ordered by
`(organization_id, agent_id, occurred_at)`. **Never** consulted for
authorization.

| Table | Holds |
|-------|-------|
| `agent_events` | agent.action.requested / allowed / blocked / approval_required |
| `tool_calls` | every tool invocation + record counts / destination / classification |
| `security_events` | detected threats, policy violations |
| `runtime_decisions` | policy-engine output + critical-path latency + cache hit |
| `behavior_events` | tool-call sequences + anomaly scores for baseline detection |

Schema: `apps/api/agentguard_api/events/clickhouse_schema.sql`.
Apply: `python -m agentguard_api.events.migrate` (idempotent).

## Commands

```powershell
.\tasks.ps1 db-migrate       # alembic upgrade head
.\tasks.ps1 db-revision "add X"   # autogenerate a migration
.\tasks.ps1 db-check         # fail on model/migration drift
.\tasks.ps1 events-migrate   # apply ClickHouse schema
```

## Not yet modelled

Sessions / refresh tokens / MFA secrets / SSO connections / SCIM state land with
auth in **Step 2**. Runtime rate-limit counters and policy cache live in Redis,
not Postgres.
