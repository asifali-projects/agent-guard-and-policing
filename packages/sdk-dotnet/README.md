# packages/sdk-dotnet

`AgentGuard.NET` — the .NET SDK **and** CLI. **Open-source** (PRD §68).
Targets `net8.0`; the only package dependency is
`Microsoft.Extensions.DependencyInjection.Abstractions` (for the optional DI
helper). HTTP is `HttpClient`; JSON is `System.Text.Json`.

```csharp
using AgentGuard;

using var guard = new AgentGuardClient(new AgentGuardOptions
{
    ApiKey = "ag_live_...",          // or AGENTGUARD_API_KEY / config file
    Agent = "FinanceAgent",
    Environment = "production",
});

await guard.GuardAsync("send_email", new { to, subject, body }, async (effective, ct) =>
{
    // runs only on ALLOW / REDACT; `effective` is the masked JsonObject on REDACT
    await mailer.SendAsync(effective, ct);
});
```

| Decision | Behaviour |
|---|---|
| `ALLOW` | run the callback |
| `DENY` | throw `PolicyDeniedException` |
| `APPROVAL` | throw `ApprovalRequiredException` (`.ApprovalRequestId`) |
| `REDACT` | mask the flagged paths, then run the callback |
| `RATE_LIMIT` | throw `RateLimitedException` (`.RetryAfterSeconds`) |

Every exception derives from `AgentGuardException`; the blocking ones carry
`.Result` (the full `DecisionResult`). Fail-safe (PRD §59):
`FailMode.Closed` (default) → `PolicyDeniedException` when the runtime is
unreachable; `FailMode.Open` → the callback runs.

### Lower-level API

```csharp
var result = await guard.EvaluateAsync("payment.create", new { amount = 48500 });      // no enforcement
var check  = await guard.CheckAsync("payment.create", new { amount = 48500 });          // enforce + redact
var status = await guard.WaitForApprovalAsync(ex.ApprovalRequestId!);                   // poll until decided
var agents = await guard.Api.GetAsync("/v1/agents");                                    // raw control-plane calls
```

### ASP.NET Core / generic host

```csharp
builder.Services.AddAgentGuard(o => o.Agent = "SupportBot");
// ...
var guard = app.Services.GetRequiredService<AgentGuardClient>();
```

Config resolution (each field independently): explicit `AgentGuardOptions` /
`configure` callback → env var (`AGENTGUARD_API_KEY`, `AGENTGUARD_BASE_URL`,
`AGENTGUARD_AGENT`, …) → `~/.agentguard/config.json` → default.

## CLI

`tools/AgentGuard.Cli` builds an `agentguard` executable:

```
agentguard login
agentguard whoami
agentguard agents list
agentguard policy validate rules.json
agentguard scan
agentguard logs [--decision deny]
agentguard redteam run --agent X --profile quick --fail-on high    # CI gate (PRD §21)
agentguard mcp scan [--server NAME]
agentguard deploy --policies ./policies --fail-on high             # CI gate (PRD §60)
```

## Develop

```bash
dotnet build src/AgentGuard/AgentGuard.csproj -warnaserror
dotnet test  tests/AgentGuard.Tests/AgentGuard.Tests.csproj
dotnet run   --project tools/AgentGuard.Cli -- agents list
```

## Layout

```
src/AgentGuard/
├── AgentGuardClient.cs   facade — identity, GuardAsync/CheckAsync/EvaluateAsync
├── RuntimeApi.cs         internal HttpClient wrapper
├── Decision.cs           Decision + FailMode enums
├── DecisionResult.cs     DecisionResult + wire DTO
├── Redaction.cs          apply redaction paths to a JsonObject
├── AgentGuardOptions.cs  option > env > ~/.agentguard/config.json
├── Exceptions.cs         AgentGuardException hierarchy
└── ServiceCollectionExtensions.cs   AddAgentGuard(...)
tools/AgentGuard.Cli/     the `agentguard` command
tests/AgentGuard.Tests/   xunit — mirrors the Python/TS suites
```

Full documentation: [`../../docs/SDK.md`](../../docs/SDK.md).
