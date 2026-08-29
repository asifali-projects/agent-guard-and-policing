using System.Text;
using System.Text.Json;

using AgentGuard;

return await CliRunner.RunAsync(args).ConfigureAwait(false);

internal static class CliRunner
{
    private static readonly Dictionary<string, int> SeverityRank = new()
    {
        ["info"] = 0, ["low"] = 1, ["medium"] = 2, ["high"] = 3, ["critical"] = 4,
    };

    private const string Help = """
        agentguard — secure your AI agents from the command line

        usage: agentguard [--api-key KEY] [--base-url URL] <command>

        commands:
          login                    save an API key to ~/.agentguard/config.json
          whoami                   show the authenticated principal
          agents list              list the agent inventory
          policy validate <file>   validate a policy spec (JSON) without saving
          scan                     per-agent risk posture summary
          logs [--limit] [--decision]
          redteam run --agent NAME [--environment] [--profile] [--fail-on]
          mcp scan [--server NAME]
          deploy [--policies DIR] [--agent NAME] [--environment] [--profile] [--fail-on]
        """;

    public static async Task<int> RunAsync(string[] args)
    {
        var flags = ParseFlags(args, out var positionalList);
        var p = positionalList.ToArray();
        if (p.Length == 0 || flags.ContainsKey("help") || flags.ContainsKey("h"))
        {
            Console.WriteLine(Help);
            return 0;
        }

        try
        {
            return p switch
            {
                ["login", ..] => await LoginAsync(flags),
                ["whoami", ..] => await WhoAmIAsync(flags),
                ["agents", "list", ..] => await AgentsListAsync(flags),
                ["policy", "validate", var file, ..] => await PolicyValidateAsync(flags, file),
                ["scan", ..] => await ScanAsync(flags),
                ["logs", ..] => await LogsAsync(flags),
                ["redteam", "run", ..] => await RedTeamRunAsync(flags),
                ["mcp", "scan", ..] => await McpScanAsync(flags),
                ["deploy", ..] => await DeployAsync(flags),
                _ => Fail($"unknown command: {string.Join(' ', p)}"),
            };
        }
        catch (AgentGuardException ex)
        {
            return Fail(ex.Message);
        }
    }

    private static AgentGuardClient Client(IReadOnlyDictionary<string, string> flags)
    {
        var options = AgentGuardOptions.FromEnvironment();
        if (flags.TryGetValue("api-key", out var key))
        {
            options.ApiKey = key;
        }

        if (flags.TryGetValue("base-url", out var baseUrl))
        {
            options.BaseUrl = baseUrl;
        }

        return new AgentGuardClient(options);
    }

    private static async Task<int> LoginAsync(IReadOnlyDictionary<string, string> flags)
    {
        var apiKey = flags.GetValueOrDefault("api-key")
            ?? Environment.GetEnvironmentVariable("AGENTGUARD_API_KEY");
        if (string.IsNullOrEmpty(apiKey))
        {
            Console.Error.Write("AgentGuard API key (input is visible): ");
            apiKey = Console.ReadLine()?.Trim();
        }

        if (string.IsNullOrEmpty(apiKey))
        {
            return Fail("no API key provided");
        }

        var options = AgentGuardOptions.FromEnvironment();
        options.ApiKey = apiKey;
        if (flags.TryGetValue("base-url", out var baseUrl))
        {
            options.BaseUrl = baseUrl;
        }

        using var client = new AgentGuardClient(options);
        try
        {
            await client.Api.GetAsync("/v1/agents");
        }
        catch (AgentGuardException ex)
        {
            return Fail($"credentials rejected: {ex.Message}");
        }

        var path = AgentGuardOptions.Save(new Dictionary<string, string?>
        {
            ["api_key"] = apiKey,
            ["base_url"] = options.NormalisedBaseUrl,
        });
        Console.WriteLine($"saved {path}");
        return 0;
    }

    private static async Task<int> WhoAmIAsync(IReadOnlyDictionary<string, string> flags)
    {
        using var client = Client(flags);
        try
        {
            var me = await client.Api.GetAsync("/v1/auth/me");
            var org = me.TryGetProperty("active_organization_id", out var o) ? o.ToString() : "-";
            Console.WriteLine($"{me.GetProperty("email").GetString()}  org={org}");
        }
        catch (AgentGuardException)
        {
            Console.WriteLine("authenticated as an API key");
        }

        return 0;
    }

    private static async Task<int> AgentsListAsync(IReadOnlyDictionary<string, string> flags)
    {
        using var client = Client(flags);
        var rows = (await client.Api.GetAsync("/v1/agents")).EnumerateArray().ToList();
        if (rows.Count == 0)
        {
            Console.WriteLine("no agents");
            return 0;
        }

        var width = rows.Max(r => r.GetProperty("name").GetString()!.Length);
        foreach (var r in rows)
        {
            var risk = r.TryGetProperty("risk_score", out var rs) && rs.ValueKind == JsonValueKind.Number
                ? rs.GetInt32().ToString()
                : "-";
            Console.WriteLine(
                $"{r.GetProperty("name").GetString()!.PadRight(width)}  " +
                $"{r.GetProperty("environment").GetString()!.PadRight(11)}  " +
                $"{r.GetProperty("status").GetString()!.PadRight(9)}  risk={risk}");
        }

        return 0;
    }

    private static async Task<int> PolicyValidateAsync(
        IReadOnlyDictionary<string, string> flags, string file)
    {
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(file));
        var spec = doc.RootElement.TryGetProperty("spec", out var s) ? s : doc.RootElement;

        using var client = Client(flags);
        var result = await client.Api.PostAsync("/v1/policies/validate", new { spec });
        if (result.GetProperty("valid").GetBoolean())
        {
            Console.WriteLine($"OK — {result.GetProperty("rule_count").GetInt32()} rule(s)");
            return 0;
        }

        foreach (var err in result.GetProperty("errors").EnumerateArray())
        {
            Console.Error.WriteLine($"error: {err.GetString()}");
        }

        return 1;
    }

    private static async Task<int> ScanAsync(IReadOnlyDictionary<string, string> flags)
    {
        using var client = Client(flags);
        var rows = (await client.Api.GetAsync("/v1/agents")).EnumerateArray().ToList();
        if (rows.Count == 0)
        {
            Console.WriteLine("no agents to scan — run `agentguard login` and connect one");
            return 0;
        }

        int Risk(JsonElement r) =>
            r.TryGetProperty("risk_score", out var v) && v.ValueKind == JsonValueKind.Number
                ? v.GetInt32()
                : 0;

        var hot = rows.Count(r => Risk(r) >= 65);
        Console.WriteLine($"{rows.Count} agent(s) scanned; {hot} at high/critical risk");
        foreach (var r in rows.OrderByDescending(Risk))
        {
            Console.WriteLine($"  {r.GetProperty("name").GetString()!.PadRight(24)} risk={Risk(r)}");
        }

        return 0;
    }

    private static async Task<int> LogsAsync(IReadOnlyDictionary<string, string> flags)
    {
        using var client = Client(flags);
        var query = new Dictionary<string, string?>
        {
            ["limit"] = flags.GetValueOrDefault("limit") ?? "20",
            ["decision"] = flags.GetValueOrDefault("decision"),
        };
        var body = await client.Api.GetAsync("/v1/audit/events", query);
        var items = body.ValueKind == JsonValueKind.Array
            ? body
            : body.GetProperty("items");
        foreach (var e in items.EnumerateArray())
        {
            var decision = e.TryGetProperty("decision", out var d) && d.ValueKind == JsonValueKind.String
                ? d.GetString()!
                : "-";
            var actor = e.TryGetProperty("actor_id", out var a) ? a.ToString() : "";
            Console.WriteLine(
                $"{e.GetProperty("occurred_at").GetString()}  " +
                $"{(e.GetProperty("action").GetString() ?? "").PadRight(22)}  " +
                $"{decision.PadRight(9)}  {actor}");
        }

        return 0;
    }

    private static async Task<int> RedTeamRunAsync(IReadOnlyDictionary<string, string> flags)
    {
        var agent = flags.GetValueOrDefault("agent")
            ?? Environment.GetEnvironmentVariable("AGENTGUARD_AGENT");
        if (string.IsNullOrEmpty(agent))
        {
            return Fail("--agent is required (or set AGENTGUARD_AGENT)");
        }

        var environment = flags.GetValueOrDefault("environment") ?? "production";
        var profile = flags.GetValueOrDefault("profile") ?? "standard";
        var failOn = flags.GetValueOrDefault("fail-on");

        using var client = Client(flags);
        var agentId = await client.Api.ResolveAgentIdAsync(agent, environment);
        var assessment = await client.Api.PostAsync(
            "/v1/redteam/assessments",
            new { agent_id = agentId, profile, environment });
        var summary = assessment.GetProperty("summary");
        Console.WriteLine(
            $"{agent}: {summary.GetProperty("passed").GetInt32()}/{summary.GetProperty("total").GetInt32()} " +
            $"defended, {summary.GetProperty("failed").GetInt32()} finding(s)");

        if (failOn is null || !summary.TryGetProperty("by_severity", out _))
        {
            return 0;
        }

        var threshold = SeverityRank.GetValueOrDefault(failOn, 99);
        var findings = await client.Api.GetAsync(
            "/v1/redteam/findings",
            new Dictionary<string, string?> { ["agent_id"] = agentId, ["status"] = "open" });
        var blockers = findings.EnumerateArray()
            .Where(f => SeverityRank.GetValueOrDefault(f.GetProperty("severity").GetString()!, 0) >= threshold)
            .ToList();
        if (blockers.Count == 0)
        {
            return 0;
        }

        Console.Error.WriteLine($"\n{blockers.Count} finding(s) at/above {failOn} — failing.");
        foreach (var f in blockers)
        {
            Console.Error.WriteLine($"  [{f.GetProperty("severity").GetString()}] {f.GetProperty("title").GetString()}");
        }

        return 1;
    }

    private static async Task<int> McpScanAsync(IReadOnlyDictionary<string, string> flags)
    {
        using var client = Client(flags);
        var servers = (await client.Api.GetAsync("/v1/mcp/servers")).EnumerateArray().ToList();
        if (flags.TryGetValue("server", out var name))
        {
            servers = servers.Where(s => s.GetProperty("name").GetString() == name).ToList();
            if (servers.Count == 0)
            {
                return Fail($"no MCP server named {name}");
            }
        }

        if (servers.Count == 0)
        {
            Console.WriteLine("no MCP servers registered");
            return 0;
        }

        foreach (var s in servers)
        {
            var result = await client.Api.PostAsync($"/v1/mcp/servers/{s.GetProperty("id").GetString()}/scan");
            var issues = string.Join(", ", result.GetProperty("issues").EnumerateArray().Select(i => i.GetString()));
            Console.WriteLine(
                $"{s.GetProperty("name").GetString()!.PadRight(24)} " +
                $"{result.GetProperty("severity").GetString()!.PadRight(9)} " +
                $"{result.GetProperty("status").GetString()!.PadRight(16)} {(issues.Length == 0 ? "clean" : issues)}");
        }

        return 0;
    }

    private static async Task<int> DeployAsync(IReadOnlyDictionary<string, string> flags)
    {
        var environment = flags.GetValueOrDefault("environment") ?? "production";
        var profile = flags.GetValueOrDefault("profile") ?? "quick";
        var failOn = flags.GetValueOrDefault("fail-on") ?? "high";
        var threshold = SeverityRank.GetValueOrDefault(failOn, 3);

        using var client = Client(flags);
        var lines = new StringBuilder().AppendLine("## AgentGuard Security").AppendLine();
        var failed = false;

        if (flags.TryGetValue("policies", out var dir))
        {
            var bad = 0;
            foreach (var file in Directory.EnumerateFiles(dir, "*.json"))
            {
                using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(file));
                var spec = doc.RootElement.TryGetProperty("spec", out var s) ? s : doc.RootElement;
                var r = await client.Api.PostAsync("/v1/policies/validate", new { spec });
                if (!r.GetProperty("valid").GetBoolean())
                {
                    bad++;
                    failed = true;
                }
            }

            lines.AppendLine($"- Policies: {(bad == 0 ? "all valid" : $"{bad} invalid")}");
        }

        var targets = flags.TryGetValue("agent", out var one)
            ? new List<string> { one }
            : (await client.Api.GetAsync("/v1/agents")).EnumerateArray()
                .Where(a => a.GetProperty("environment").GetString() == environment)
                .Select(a => a.GetProperty("name").GetString()!)
                .ToList();

        foreach (var name in targets)
        {
            var agentId = await client.Api.ResolveAgentIdAsync(name, environment);
            var assessment = await client.Api.PostAsync(
                "/v1/redteam/assessments",
                new { agent_id = agentId, profile, environment });
            var summary = assessment.GetProperty("summary");
            var blockers = 0;
            if (summary.TryGetProperty("by_severity", out var bySeverity))
            {
                foreach (var kv in bySeverity.EnumerateObject())
                {
                    if (SeverityRank.GetValueOrDefault(kv.Name, 0) >= threshold)
                    {
                        blockers += kv.Value.GetInt32();
                    }
                }
            }

            if (blockers > 0)
            {
                failed = true;
            }

            lines.AppendLine(
                $"- [{(blockers > 0 ? "FAIL" : "ok")}] **{name}**: " +
                $"{summary.GetProperty("passed").GetInt32()}/{summary.GetProperty("total").GetInt32()} defended, " +
                $"{summary.GetProperty("failed").GetInt32()} finding(s)");
        }

        lines.AppendLine().AppendLine(
            $"**{(failed ? "Deployment blocked" : "Checks passed")}** (fail-on: {failOn})");
        Console.WriteLine(lines.ToString());
        if (flags.TryGetValue("pr-comment", out var prPath))
        {
            await File.WriteAllTextAsync(prPath, lines.ToString());
        }

        return failed ? 1 : 0;
    }

    private static Dictionary<string, string> ParseFlags(string[] args, out List<string> positionals)
    {
        var flags = new Dictionary<string, string>(StringComparer.Ordinal);
        positionals = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                var name = arg[2..];
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    flags[name] = args[++i];
                }
                else
                {
                    flags[name] = "true";
                }
            }
            else if (arg is "-h")
            {
                flags["h"] = "true";
            }
            else
            {
                positionals.Add(arg);
            }
        }

        return flags;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine($"error: {message}");
        return 1;
    }
}
