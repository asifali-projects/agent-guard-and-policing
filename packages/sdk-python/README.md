# packages/sdk-python

`agentguard` — the Python SDK. **Open-source** (PRD §68).

Target developer experience (PRD §71): first success in 5–10 minutes.

```python
from agentguard import AgentGuard

guard = AgentGuard(api_key="ag_live_xxx")
protected_agent = guard.protect(agent=my_agent)

@guard.tool
def send_email(to, subject, body):
    ...
```

Responsibilities (PRD §37): identity, tracing, tool interception, policy
evaluation, runtime protection, telemetry.

Implemented in **Step 5**. TypeScript and .NET SDKs follow in **Step 13**.
