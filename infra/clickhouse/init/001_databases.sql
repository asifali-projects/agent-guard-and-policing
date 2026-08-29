-- Runs once on first ClickHouse boot.
-- Event table definitions are owned by application migrations (Step 1 / Step 8).
CREATE DATABASE IF NOT EXISTS agentguard_events;
