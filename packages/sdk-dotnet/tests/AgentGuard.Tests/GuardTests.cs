using System.Text.Json.Nodes;

using Xunit;

namespace AgentGuard.Tests;

public sealed class GuardTests
{
    private static (AgentGuardClient Client, FakeHandler Handler) Make(
        Dictionary<string, Dictionary<string, object?>>? decisions = null,
        FailMode failMode = FailMode.Closed)
    {
        var handler = new FakeHandler(decisions);
        var client = new AgentGuardClient(
            new AgentGuardOptions
            {
                ApiKey = "ag_dev_test_secret",
                BaseUrl = "http://test",
                Agent = "TestAgent",
                Environment = "production",
                FailMode = failMode,
            },
            new HttpClient(handler));
        return (client, handler);
    }

    private static Dictionary<string, Dictionary<string, object?>> Decision(
        string tool, params (string Key, object? Value)[] fields)
    {
        return new Dictionary<string, Dictionary<string, object?>>
        {
            [tool] = fields.ToDictionary(f => f.Key, f => f.Value),
        };
    }

    [Fact]
    public async Task Allow_runs_the_callback_and_forwards_parameters()
    {
        var (client, handler) = Make();

        var result = await client.GuardAsync(
            "add",
            new { a = 2, b = 3 },
            (effective, _) => Task.FromResult(
                effective["a"]!.GetValue<int>() + effective["b"]!.GetValue<int>()));

        Assert.Equal(5, result);
        Assert.Equal("add", handler.EvaluateCalls[0].GetProperty("tool").GetString());
        Assert.Equal(2, handler.EvaluateCalls[0].GetProperty("parameters").GetProperty("a").GetInt32());
    }

    [Fact]
    public async Task Deny_throws_PolicyDenied_with_reasons()
    {
        var (client, _) = Make(Decision("wire_money", ("decision", "DENY"), ("reasons", new[] { "policy FIN-1" })));

        var ex = await Assert.ThrowsAsync<PolicyDeniedException>(
            () => client.CheckAsync("wire_money", new { amount = 1000 }));

        Assert.Contains("FIN-1", ex.Message);
        Assert.Equal(AgentGuard.Decision.Deny, ex.Result.Decision);
    }

    [Fact]
    public async Task Approval_throws_with_the_request_id()
    {
        var (client, _) = Make(Decision(
            "pay",
            ("decision", "APPROVAL"),
            ("approval_request_id", "abc-123"),
            ("reasons", new[] { "needs sign-off" })));

        var ex = await Assert.ThrowsAsync<ApprovalRequiredException>(
            () => client.CheckAsync("pay", new { vendor = "acme", amount = 50000 }));

        Assert.Equal("abc-123", ex.ApprovalRequestId);
    }

    [Fact]
    public async Task Redact_masks_the_flagged_argument_before_the_call()
    {
        var (client, _) = Make(Decision(
            "send_email",
            ("decision", "REDACT"),
            ("redactions", new[] { "parameters.body" })));

        JsonObject? seen = null;
        await client.GuardAsync(
            "send_email",
            new { to = "x@y.com", body = "my SSN is 123-45-6789" },
            (effective, _) =>
            {
                seen = effective;
                return Task.CompletedTask;
            });

        Assert.Equal("x@y.com", seen!["to"]!.GetValue<string>());
        Assert.Equal(Redaction.Redacted, seen["body"]!.GetValue<string>());
    }

    [Fact]
    public async Task RateLimit_throws_with_retry_after_seconds()
    {
        var (client, _) = Make(Decision(
            "search",
            ("decision", "RATE_LIMIT"),
            ("rate_limit", new Dictionary<string, object?> { ["retry_after_seconds"] = 42 })));

        var ex = await Assert.ThrowsAsync<RateLimitedException>(
            () => client.CheckAsync("search", new { q = "hello" }));

        Assert.Equal(42, ex.RetryAfterSeconds);
    }

    [Fact]
    public async Task Fail_closed_converts_an_unreachable_runtime_into_PolicyDenied()
    {
        var (client, handler) = Make(failMode: FailMode.Closed);
        handler.Unreachable = true;
        client.SetAgentId(FakeHandler.AgentId);

        await Assert.ThrowsAsync<PolicyDeniedException>(
            () => client.CheckAsync("t", new { }));
    }

    [Fact]
    public async Task Fail_open_runs_the_callback_when_the_runtime_is_down()
    {
        var (client, handler) = Make(failMode: FailMode.Open);
        handler.Unreachable = true;
        client.SetAgentId(FakeHandler.AgentId);

        var ran = await client.GuardAsync("t", new { }, (_, _) => Task.FromResult("ran"));
        Assert.Equal("ran", ran);
    }

    [Fact]
    public async Task Identity_resolution_reuses_an_existing_agent()
    {
        var (client, _) = Make();
        Assert.Equal(FakeHandler.AgentId, await client.GetAgentIdAsync());
    }

    [Fact]
    public async Task WaitForApproval_returns_the_decided_status()
    {
        var (client, _) = Make();
        var status = await client.WaitForApprovalAsync(
            "abc-123", pollInterval: TimeSpan.FromMilliseconds(1));
        Assert.Equal("approved", status);
    }
}
