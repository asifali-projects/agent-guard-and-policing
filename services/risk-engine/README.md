# services/risk-engine

Multi-factor risk scoring (Python).

Factors (PRD §26): Identity Risk + Permission Risk + Tool Risk + Data Risk +
Destination Risk + Behavior Risk + Historical Risk.

Output:

```json
{ "risk_score": 94, "severity": "critical", "decision": "BLOCK" }
```

Implemented in **Step 4**. Called synchronously on the runtime critical path
(must stay lightweight — PRD §25, §58 p95 < 50 ms for cached checks).
