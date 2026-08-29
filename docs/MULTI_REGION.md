# Multi-Region & Data Residency (Step 14)

Covers PRD §76 — "US / EU / Middle East / APAC. Each region: Control Plane +
Data Plane + Event Store. Customer chooses data residency."

## Model

**One deployment = one region.** There is no cross-region database, no global
router in the application tier. Each region (`us`, `eu`, `me`, `apac`) runs a
complete, isolated AgentGuard stack — its own Postgres, Redis, ClickHouse,
Redpanda, MinIO, API, web, and `ai-analyst` service. An organization is pinned
to one **home region at creation** and its data (orgs, users, agents, policies,
findings, incidents, audit log, events, evidence) never leaves it.

The customer "chooses" residency by **signing up at that region's URL**
(`https://eu.app.agentguard.example`). The dashboard shows a region picker on
the sign-up form and redirects the browser to the chosen region's app.

## Region enum

`Region` (`models/enums.py`) — `us` · `eu` · `me` · `apac`.
`Organization.region` is `enum_column(Region)` (migration `89d72fc74981`),
defaulted to the deployment's region and **immutable** thereafter (`OrgUpdate`
has no `region` field).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AGENTGUARD_REGION` | `us` | which region this deployment serves |
| `AGENTGUARD_REGIONS` | `us\|United States\|http://localhost:8010\|http://localhost:3010` | discovery map: `code\|name\|api_url\|web_url`, comma-separated |

Each region also gets its **own** `DATABASE_URL`, `REDIS_URL`,
`CLICKHOUSE_HOST`, `KAFKA_BOOTSTRAP_SERVERS`, `S3_*`, and `AGENTGUARD_SECRET_KEY`
— they are separate infrastructure.

## Discovery — `GET /v1/regions` (public, no auth)

```json
{
  "current": "eu",
  "regions": [
    { "code": "us", "name": "United States", "api_url": "https://us.api…", "web_url": "https://us.app…", "current": false },
    { "code": "eu", "name": "European Union", "api_url": "https://eu.api…", "web_url": "https://eu.app…", "current": true }
  ]
}
```

SDKs and the dashboard call this before authenticating to route to the right
region.

## The residency guard

`regions.assert_servable(region)` raises **`421 Misdirected Request`** unless
`region` is the one this deployment serves, with headers:

```
X-AgentGuard-Region:     us
X-AgentGuard-Region-Url:  https://us.api.agentguard.example
```

It is enforced in two places:

1. **Every authenticated request** — `auth.dependencies.get_principal` loads the
   active org and calls `assert_servable(org.region)`. In normal operation this
   never fires (sessions, users, and orgs in a region are all that region); it
   is defence-in-depth against a mis-homed row or a misconfigured deployment.
2. **Creation** — `POST /v1/auth/register` and `POST /v1/organizations` reject a
   `region` that isn't this deployment's, pointing the caller at the correct
   endpoint. If `region` is omitted, the deployment's region is used.

The dashboard turns a 421 into "Your account's data is in the **US** region —
[Continue there →]".

## `/v1/auth/me` additions

```jsonc
{
  "region": "eu",              // the region this deployment serves
  "active_region": "eu",       // the active org's home region
  "memberships": [ { "…": "…", "region": "eu" } ]
}
```

## Deploying a second region

Point a second copy of `infra/docker-compose.yml` (or the Helm chart) at fresh
infrastructure with `AGENTGUARD_REGION=eu` and an `AGENTGUARD_REGIONS` map that
lists both regions. Run `alembic upgrade head` + `python -m
agentguard_api.rbac.seed` against the EU database. DNS / edge routing
(`eu.api.*`, `eu.app.*`) is an infrastructure concern — the application only
needs to know its own region and the discovery map.

## Deferred

Global identity directory (same email → linked accounts across regions),
automated cross-region org migration, region-aware SDK auto-routing (today the
SDK 421 surfaces as a normal error carrying the target URL), and per-region
read replicas.
