# packages/sdk-typescript

`@agentguard/sdk` — the TypeScript SDK. **Open-source** (PRD §68).

```ts
import { AgentGuard } from "@agentguard/sdk";

const guard = new AgentGuard({ apiKey: process.env.AGENTGUARD_API_KEY });
```

Same responsibilities as the Python SDK (identity, tracing, tool interception,
policy evaluation, runtime protection, telemetry).

Implemented in **Step 13**.
