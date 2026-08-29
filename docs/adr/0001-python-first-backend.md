# ADR 0001 — Python-first backend

- **Status:** accepted
- **Date:** 2026-08-29
- **Context step:** 0

## Context

PRD §54 suggests ASP.NET Core for the API with Python for AI/detection services.
The product also ships SDKs for Python, TypeScript and .NET (§37).

The heaviest, most differentiated engineering is in the security plane:
red-team engine, risk engine, behavioral detection, DLP, AI analyst — all
naturally Python (ML/NLP ecosystem). Splitting the API into .NET means two
runtimes, two dependency systems, duplicated domain models, and a serialization
boundary on the hot path between the API and the policy/risk engines.

## Decision

Build the API and workers in **Python 3.11** (FastAPI, async SQLAlchemy). The
policy engine is a pure-Python library embeddable both in the API and in the
Python SDK. The **.NET SDK is still delivered** (Step 13) — it talks to the
runtime API over HTTP like any other client.

## Consequences

- One language, one set of domain models across API, workers, policy engine,
  and security services.
- The runtime critical path stays in-process (no cross-runtime hop).
- `.NET`/`TypeScript` customers are served through SDKs + the REST API, not by a
  native backend in their language.
- If a future requirement demands a .NET service, it joins as another service
  behind the gateway — this decision does not preclude that.
