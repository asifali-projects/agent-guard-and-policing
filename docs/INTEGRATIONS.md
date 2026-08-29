# Integrations, CI/CD & Billing (Step 9)

Covers PRD §43 (events), §60–61 (CI/CD), §62 (integrations), §64–65 (billing,
metering).

## Event bus — `agentguard_api/events/bus.py`

`publish(session, organization_id=, event_type=, payload=)` fans a canonical
event out to every enabled webhook and notification/SIEM integration for the
org. **Best-effort and inline** — a slow or failing endpoint never blocks or
breaks the request that raised the event (Kafka-fronted async delivery is a
later step).

Canonical events (PRD §43): `agent.action.blocked`,
`agent.action.approval_required`, `threat.detected`, `incident.created`,
`incident.updated`, `redteam.completed`, `agent.registered`, `finding.opened`,
`policy.violated`.

Security-relevant events are also written to ClickHouse `security_events`.

Wired at the source: a runtime `DENY` → `agent.action.blocked`; an `APPROVAL` →
`agent.action.approval_required`; `raise_behavioral_threat` → `threat.detected`
(+ `incident.created`); incident transitions → `incident.updated`; a finished
assessment → `redteam.completed`; agent registration → `agent.registered`.

## Integrations & webhooks — `agentguard_api/integrations/`

```
GET  /v1/integrations/catalog             providers per category (PRD §62)
GET/POST/PATCH/DELETE  /v1/integrations    {provider, config, enabled}
GET/POST/PATCH/DELETE  /v1/webhooks        {url, events[], secret, enabled}
POST /v1/webhooks/{id}/test
```

| Category | Providers | Delivery |
|---|---|---|
| notifications | slack, teams, pagerduty | `{"text": …}` to `config.webhook_url`; PagerDuty Events API v2 with `config.routing_key` |
| siem | splunk, microsoft_sentinel, elastic | the full event envelope to `config.url` |
| identity / devops / ticketing / cloud | catalogued; wired case-by-case later |

**Webhook signing**: `X-AgentGuard-Signature: sha256=<hmac>` of the raw body
keyed by the webhook's secret. The secret is never returned by the API.

## CI/CD gate (PRD §60–61)

`agentguard deploy` — validate a directory of policy specs, red-team the target
agent(s), print a Markdown summary, and **exit non-zero** on findings at/above
`--fail-on`:

```bash
agentguard deploy --policies ./policies --agent FinanceAgent \
  --profile quick --fail-on high --pr-comment summary.md
```

A composite GitHub Action wraps it — `.github/actions/agentguard/action.yml`:

```yaml
- uses: your-org/agentguard/.github/actions/agentguard@v1
  with:
    api-key: ${{ secrets.AGENTGUARD_API_KEY }}
    base-url: https://api.agentguard.example
    policies: ./policies
    fail-on: high
    comment: "true"          # posts the summary on the PR
```

## Billing & usage metering — `agentguard_api/billing/`

Usage is metered with **Redis counters** (one `INCR` per event — cheap enough
for the runtime hot path): `runtime_actions`, `runtime_blocked`, `redteam_tests`,
`data_scans`, per calendar month. `agents` / `mcp_servers` / `users` are counted
live from Postgres.

```
GET  /v1/billing/plans           public tiers + limits (PRD §64)
GET  /v1/billing/subscription    current plan + status + this-period usage + over_limit flags
POST /v1/billing/subscription    {plan_code} — org.billing permission; Enterprise → contact sales
```

Limits are **advisory** (`over_limit` flags), not hard caps. A worker flushes
the Redis counters into `usage_records` for invoicing; Stripe / payment-processor
wiring (PRD §65) is intentionally out of scope in this build.

## Frontend

**Integrations** page (connect Slack/PagerDuty/SIEM, manage webhooks with a
per-event subscription grid + Test button) and **Billing** page (usage tiles vs
plan limits, plan switcher).

## Deferred

Kafka-fronted async delivery + retries with backoff, OAuth flows for
Okta/Entra/Auth0/GitHub App, Jira/ServiceNow ticket creation, delivery logs,
Stripe subscriptions + invoices, hard plan enforcement.
