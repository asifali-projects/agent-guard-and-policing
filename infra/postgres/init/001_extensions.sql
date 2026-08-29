-- Runs once on first container boot (empty data dir).
-- Schema + tables are owned by application migrations (Step 1), not this file.

-- uuid_generate_v4(), gen_random_uuid() live here / in pgcrypto
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- trigram indexes for inventory search
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
-- pgvector: threat-intel embeddings may live in Postgres before Qdrant is wired
CREATE EXTENSION IF NOT EXISTS "vector";
