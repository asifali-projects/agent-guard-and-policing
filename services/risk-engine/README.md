# services/risk-engine

Multi-factor risk scoring (PRD §26).

**The synchronous, critical-path scorer is implemented in the API** at
`apps/api/agentguard_api/risk/` (Step 4) — see
[`../../docs/RISK_DLP.md`](../../docs/RISK_DLP.md). It runs in-process because it
sits on the runtime hot path (PRD §25, §58).

This directory is reserved for the **heavier, asynchronous** risk work that runs
off the event stream:

- recomputing per-agent risk trends from ClickHouse history
- factor-weight tuning / backtesting
- feeding the agent security-posture score (PRD §14) and dashboard

Not implemented yet.
