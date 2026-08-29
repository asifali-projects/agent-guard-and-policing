# Behavioral Detection, Incidents & Agent Graph (Step 8)

Covers PRD §28 (behavioral detection), §30 (incident response), §31–32 (agent
graph / blast radius), §33 (audit export).

## Behavioral baseline — `agentguard_api/detection/`

Each agent gets one `behavior_profiles` row, updated **synchronously** on every
runtime evaluation (one indexed upsert):

- `tool_counts` — how often each tool is called
- `tool_max_volume` — largest `records`/`count`/… parameter seen per tool
- `destinations`, `classifications` — everything the agent has ever touched
- `recent_sequence` — the last 25 tool names

`anomaly.score_anomaly(profile, …)` is pure and scores a new call 0–100:

| Signal | Weight |
|---|---|
| first observed use of the tool | +45 |
| volume ≫ the tool's baseline max | up to +50 |
| new destination | +25 |
| first time handling this data class | +18 |
| same tool repeated 5+ times (loop) | +30 |
| rare tool (< 3% of calls) | +12 |

Cold start (< 8 calls) returns a flat 10.

### Feeding the risk engine (replaces the Step 4 heuristic)

The `behavior` factor is now the anomaly score. A **severe** anomaly also floors
the composite risk (PRD §28 — "Behavioral anomaly — risk 94"):

```
anomaly ≥ 90  →  risk_score = max(risk_score, 82)
anomaly ≥ 75  →  risk_score = max(risk_score, 66)
```

When an anomalous call is observed, `raise_behavioral_threat` writes a
`threats` row (deduped within 1 h) and, at score ≥ 85, auto-opens an `Incident`.

## Incidents — `agentguard_api/incidents/`

```
GET  /v1/threats[?status=]           GET  /v1/incidents[?status=&severity=]
POST /v1/threats/{id}/resolve        POST /v1/incidents            {title, severity, agent_id?}
                                     GET  /v1/incidents/{id}        (+ timeline)
                                     POST /v1/incidents/{id}/transition   {status}
                                     POST /v1/incidents/{id}/actions      {action, tool?}
```

**Lifecycle** (PRD §30): `detected → investigating → contained → resolved →
closed`, with the illegal transitions rejected (409) and `contained_at` /
`resolved_at` / `closed_at` stamped.

**Response actions** (PRD §30):

| Action | Effect |
|---|---|
| `pause_agent` / `resume_agent` | flips `agent.status`; **a paused agent is denied every runtime call** |
| `block_tool` | creates + binds a deny policy `IR-<INC>-<tool>` |
| `notify_security` | queued for the notifications worker (Step 9) |

Every transition and action appends an `incident_events` timeline entry and an
`audit_events` row.

## Agent graph & blast radius — `agentguard_api/graph/`

```
GET /v1/agents/{id}/graph          nodes + edges: agent → tool → destination / data / mcp
GET /v1/agents/{id}/blast-radius   "if this agent is compromised, what can it access?"
```

Built from the behaviour profile (what the agent *has* done) plus `agent_tools`
grants and tool metadata. Blast radius returns tool / database / API / MCP
counts, external destinations, data classes handled, and a
`potential_impact ∈ {LOW, MEDIUM, HIGH, CRITICAL}` weighted by agent risk,
high/critical tools, restricted data, external reach and MCP exposure.

## Audit export (PRD §33)

`GET /v1/audit/events.csv?since=&limit=` — chronological CSV including the
hash-chain columns (`prev_hash`, `entry_hash`) so an auditor can re-verify
offline.

## Frontend

New pages: **Threats** (signals + resolve), **Incidents** (list + timeline +
transitions + response actions). Agent detail gains a **Graph** tab (reachability
+ blast radius). Audit page gains **Export CSV**.

## Deferred

ClickHouse-backed baselines + sequence n-gram models in a worker, cross-agent
correlation, agent-to-agent edges in the graph, a visual graph renderer,
`revoke_permission` / `disable_credential` response actions, worker-backed deep
red-team assessments.
