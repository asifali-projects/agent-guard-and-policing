# apps/workers

Async background workers (Python). Consume the Redpanda event stream and run
scheduled jobs.

Planned consumers / jobs:

| Worker | Purpose | Step |
|--------|---------|------|
| `event_ingestor` | Redpanda → ClickHouse fan-out of runtime events | 1 / 8 |
| `redteam_runner` | Execute queued red-team assessments in a sandbox | 6 |
| `continuous_redteam` | Trigger re-tests on deploy / model / prompt / tool / MCP change (PRD §21) | 6 |
| `behavior_baseline` | Roll up per-agent behavioral baselines, emit anomalies (PRD §28) | 8 |
| `usage_metering` | Aggregate usage records for billing (PRD §65) | 9 |
| `notifier` | Deliver Slack / Teams / PagerDuty / webhook notifications | 9 |

Not implemented yet — scaffolded in Step 0 so the layout is fixed.
