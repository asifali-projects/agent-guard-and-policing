# packages/sdk-python

`agentguard` — the Python SDK **and** CLI. **Open-source** (PRD §68).
`pip install agentguard` gives you both.

```python
from agentguard import AgentGuard

guard = AgentGuard(api_key="ag_live_...", agent="FinanceAgent", environment="production")

@guard.tool
def send_email(to, subject, body):
    ...        # runs only if the runtime returns ALLOW; REDACT masks flagged args
```

```
agentguard login          # save an API key
agentguard agents list
agentguard policy validate rules.json
agentguard scan           # per-agent risk posture
agentguard logs
```

Full documentation: [`../../docs/SDK.md`](../../docs/SDK.md).

## Develop

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest -q
```

The API installs this package editable so the end-to-end test
(`apps/api/tests/test_sdk_integration.py`) can drive a live server.

## Layout

```
agentguard/
├── __init__.py     public API: AgentGuard, Decision, exceptions
├── guard.py        AgentGuard — identity, @tool, check(), protect()
├── client.py       sync httpx wrapper for the runtime + control API
├── decision.py     DecisionResult
├── redact.py       apply redaction paths to arguments
├── config.py       arg > env > ~/.agentguard/config.toml
├── exceptions.py   AgentGuardError hierarchy
└── cli/            the `agentguard` command (click)
```

TypeScript and .NET SDKs follow in **Step 13**.
