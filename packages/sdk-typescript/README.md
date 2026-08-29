# packages/sdk-typescript

`@agentguard/sdk` — the TypeScript/JavaScript SDK **and** CLI. **Open-source**
(PRD §68). Zero runtime dependencies (uses the built-in `fetch`).

```ts
import { AgentGuard } from "@agentguard/sdk";

const guard = new AgentGuard({
  apiKey: "ag_live_...",           // or AGENTGUARD_API_KEY / config file
  agent: "FinanceAgent",
  environment: "production",
});

const sendEmail = guard.tool(
  async ({ to, subject, body }: { to: string; subject: string; body: string }) => {
    // runs only if the runtime returns ALLOW; REDACT masks flagged args
  },
);
```

The wrapped function is **async**. It expects a single object of named
parameters — the shape every major agent framework uses — so redaction can map
the runtime's paths back onto the arguments.

| Decision | Behaviour |
|---|---|
| `ALLOW` | call the function |
| `DENY` | throw `PolicyDenied` |
| `APPROVAL` | throw `ApprovalRequired` (`.approvalRequestId`) |
| `REDACT` | mask the flagged paths, then call |
| `RATE_LIMIT` | throw `RateLimited` (`.retryAfterSeconds`) |

Every error extends `AgentGuardError` and carries `.result` (the full
`DecisionResult`). Fail-safe (PRD §59): `failMode: "closed"` (default) →
`PolicyDenied` when the runtime is unreachable; `"open"` → the function runs.

### Lower-level API

```ts
const result = await guard.evaluate("payment.create", { amount: 48500 });        // no enforcement
const { parameters } = await guard.check("payment.create", { amount: 48500 });   // enforce + redact
const status = await guard.waitForApproval(err.approvalRequestId!);              // poll until decided
await guard.client.get("/v1/agents");                                            // raw control-plane calls
```

Config resolution (each field independently): explicit option → env var
(`AGENTGUARD_API_KEY`, `AGENTGUARD_BASE_URL`, `AGENTGUARD_AGENT`, …) →
`~/.agentguard/config.json` → default.

## CLI

```
agentguard login                     # save an API key to ~/.agentguard/config.json
agentguard whoami
agentguard agents list
agentguard policy validate rules.json
agentguard scan                      # per-agent risk posture
agentguard logs [--decision deny]
agentguard redteam run --agent X --profile quick --fail-on high   # CI gate (PRD §21)
agentguard mcp scan [--server NAME]
agentguard deploy --policies ./policies --fail-on high            # CI gate (PRD §60)
```

## Develop

```bash
npm install
npm run typecheck
npm test          # node:test via tsx
npm run build     # -> dist/
```

## Layout

```
src/
├── index.ts     public API
├── guard.ts     AgentGuard — identity, tool(), check(), protect()
├── client.ts    fetch wrapper for the runtime + control API
├── types.ts     Decision, DecisionResult
├── redact.ts    apply redaction paths to arguments
├── config.ts    option > env > ~/.agentguard/config.json
├── errors.ts    AgentGuardError hierarchy
└── cli.ts       the `agentguard` command (node:util parseArgs)
```

Full documentation: [`../../docs/SDK.md`](../../docs/SDK.md).
