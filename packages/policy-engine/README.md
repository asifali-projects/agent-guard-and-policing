# packages/policy-engine

`agentguard-policy-engine` — deterministic policy evaluation. **Open-source**
component (PRD §68). Module: `agentguard_policy`.

The critical-path authorization decision must **not** depend on an LLM
(PRD §25). This package is pure: no I/O, no database, no network.

```python
from agentguard_policy import evaluate, EvaluationInput, CompiledPolicy, PolicySpec

policies = [
    CompiledPolicy(
        key="FIN-004",
        specificity=2,          # agent scope
        spec=PolicySpec.model_validate({
            "rules": [{
                "effect": "approval",
                "actions": ["payment.create"],
                "when": {"field": "parameters.amount", "op": "gt", "value": 5000},
            }],
        }),
    ),
]

result = evaluate(
    EvaluationInput(tool="payment.create", parameters={"amount": 48500}),
    policies,
)
result.decision            # Decision.approval
result.matched_policy_keys # ["FIN-004"]
```

## What it decides

`Decision ∈ {allow, deny, approval, redact, rate_limit}` (PRD §24), by
precedence:

```
deny > approval > rate_limit > redact > allow > default_effect > implicit allow
```

Stateful obligations — rate-limit counters, approval lookup — are **not** the
engine's job; the runtime layer (`apps/api/agentguard_api/runtime/`) resolves
those. See [`../../docs/POLICY.md`](../../docs/POLICY.md) for the spec format,
condition operators, and the hierarchy.

## Develop

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest -q
```

The API installs this package editable; see the repo root `tasks.ps1 api-install`.
