# services/red-team

Offensive security engine (PRD §18–22).

**The engine is implemented in the API** at `apps/api/agentguard_api/redteam/`
(Step 6) — catalog, sandbox, evaluator, findings — see
[`../../docs/REDTEAM.md`](../../docs/REDTEAM.md). Assessments run inline because
each test is a sub-millisecond `core_decision`.

This directory is reserved for the **worker-backed** offensive work:

- `deep` / `enterprise` profiles and large custom runs, executed off the queue
- continuous red-team triggers (PRD §21): re-test on deploy / model / prompt /
  tool / MCP change
- LLM-assisted attack generation and adaptive/iterative attacks
- driving a live agent endpoint directly (not just replaying tool calls)

Wired in Step 8 alongside the event workers.
