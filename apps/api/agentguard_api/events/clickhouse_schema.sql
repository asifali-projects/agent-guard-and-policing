-- AgentGuard event store — PRD §45.
-- High-volume runtime telemetry. NEVER used for authorization decisions.
-- Applied by `python -m agentguard_api.events.migrate` (idempotent).

CREATE DATABASE IF NOT EXISTS agentguard_events;

-- Raw agent actions (requested / allowed / blocked / approval_required) — PRD §43.
CREATE TABLE IF NOT EXISTS agentguard_events.agent_events
(
    event_id        UUID,
    occurred_at     DateTime64(3, 'UTC'),
    organization_id UUID,
    agent_id        UUID,
    agent_version   LowCardinality(String),
    environment     LowCardinality(String),
    event_type      LowCardinality(String),      -- agent.action.requested | .allowed | .blocked | .approval_required
    tool            String,
    action          LowCardinality(String),
    trace_id        String,
    request_id      String,
    payload_hash    FixedString(64),
    attributes      Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (organization_id, agent_id, occurred_at)
TTL toDateTime(occurred_at) + INTERVAL 13 MONTH;

-- Every tool invocation with its resolved parameters metadata.
CREATE TABLE IF NOT EXISTS agentguard_events.tool_calls
(
    event_id        UUID,
    occurred_at     DateTime64(3, 'UTC'),
    organization_id UUID,
    agent_id        UUID,
    tool            String,
    action          LowCardinality(String),
    duration_ms     UInt32,
    param_count     UInt16,
    record_count    UInt64,                      -- rows / records touched (PRD §28 anomaly signal)
    destination     String,
    data_classification LowCardinality(String),
    trace_id        String,
    request_id      String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (organization_id, agent_id, tool, occurred_at)
TTL toDateTime(occurred_at) + INTERVAL 13 MONTH;

-- Detected threats / policy violations feeding incident response.
CREATE TABLE IF NOT EXISTS agentguard_events.security_events
(
    event_id        UUID,
    occurred_at     DateTime64(3, 'UTC'),
    organization_id UUID,
    agent_id        UUID,
    kind            LowCardinality(String),      -- prompt_injection | secret_leak | anomaly | ...
    severity        LowCardinality(String),
    risk_score      UInt8,
    rule_id         String,
    policy_key      LowCardinality(String),
    trace_id        String,
    request_id      String,
    detail          String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (organization_id, severity, occurred_at);

-- Output of the policy decision engine for each evaluated action — PRD §24.
CREATE TABLE IF NOT EXISTS agentguard_events.runtime_decisions
(
    event_id        UUID,
    occurred_at     DateTime64(3, 'UTC'),
    organization_id UUID,
    agent_id        UUID,
    tool            String,
    action          LowCardinality(String),
    decision        LowCardinality(String),      -- allow | deny | approval | redact | rate_limit
    risk_score      UInt8,
    policy_key      LowCardinality(String),
    latency_ms      Float32,                     -- critical-path latency (PRD §57–58)
    cache_hit       UInt8,
    fail_mode       LowCardinality(String),
    trace_id        String,
    request_id      String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (organization_id, agent_id, occurred_at);

-- Behavioural signals for baseline + anomaly detection — PRD §28.
CREATE TABLE IF NOT EXISTS agentguard_events.behavior_events
(
    event_id        UUID,
    occurred_at     DateTime64(3, 'UTC'),
    organization_id UUID,
    agent_id        UUID,
    sequence_hash   String,                      -- hash of the recent tool-call sequence
    step_tool       String,
    step_index      UInt16,
    record_count    UInt64,
    anomaly_score   Float32,
    baseline_version UInt32,
    trace_id        String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (organization_id, agent_id, occurred_at);
