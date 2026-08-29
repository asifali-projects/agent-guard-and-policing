# packages/sdk-dotnet

`AgentGuard.NET` — the .NET SDK. **Open-source** (PRD §68).

```csharp
builder.Services.AddAgentGuard(options =>
{
    options.ApiKey = configuration["AgentGuard:ApiKey"];
});

app.UseAgentGuard();

[AgentGuardTool]
public async Task<Customer> GetCustomer(string id) { ... }
```

Implemented in **Step 13**.
