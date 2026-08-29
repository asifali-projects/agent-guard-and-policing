# services/ai-analyst

Natural-language security analyst (Python) — PRD §35.

Answers questions like *"Why was FinanceAgent blocked?"* or *"Which agents are
riskiest?"* over the AgentGuard control plane. **Read-only**: the tool library
only queries, and `org_id` is bound from the caller, never the model.

**Implemented in Step 12** at
[`apps/api/agentguard_api/analyst/`](../../apps/api/agentguard_api/analyst/) —
the tool library, the Claude tool-use engine, and the deterministic fallback
router. See [`../../docs/ANALYST.md`](../../docs/ANALYST.md).

This directory is the **deployment unit**. The analyst runs as its own container
off the API image with a different entrypoint:

```
uvicorn agentguard_api.analyst.asgi:app --host 0.0.0.0 --port 8000
```

`agentguard_api/analyst/asgi.py` serves only `/healthz`, `/readyz`, and
`/v1/analyst/*`, reusing the shared models, database, and engine. The compose
`ai-analyst` service (profile `apps`, port `ANALYST_PORT`, default 8020) wires
it up. Not on any enforcement path.
