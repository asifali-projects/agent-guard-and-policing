# services/detection

Behavioral baseline + anomaly detection (PRD §28).

**The synchronous detector is implemented in the API** at
`apps/api/agentguard_api/detection/` (Step 8) — a per-agent `behavior_profiles`
row updated on every runtime call, plus a pure anomaly scorer that feeds the
risk engine and raises threats. See
[`../../docs/DETECTION.md`](../../docs/DETECTION.md).

This directory is reserved for the **worker-backed** detection that runs off the
event stream:

- ClickHouse-backed baselines (longer history, seasonality)
- tool-call sequence n-gram / Markov models
- cross-agent correlation and campaign detection
- threat-intel enrichment (Qdrant attack-pattern search)

Wired in a later step alongside the other event workers.
