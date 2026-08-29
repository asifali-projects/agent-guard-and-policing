using System.Net;
using System.Text;
using System.Text.Json;

namespace AgentGuard.Tests;

/// <summary>An in-memory stand-in for the AgentGuard API.</summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    public const string AgentId = "11111111-1111-1111-1111-111111111111";

    private readonly Dictionary<string, Dictionary<string, object?>> _decisions;

    public FakeHandler(Dictionary<string, Dictionary<string, object?>>? decisions = null)
    {
        _decisions = decisions ?? new Dictionary<string, Dictionary<string, object?>>();
    }

    public List<JsonElement> EvaluateCalls { get; } = new();

    public bool Unreachable { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Unreachable)
        {
            throw new HttpRequestException("ECONNREFUSED");
        }

        var path = request.RequestUri!.AbsolutePath;
        var agent = new { id = AgentId, name = "TestAgent", environment = "production", status = "healthy" };

        if (path == "/v1/agents" && request.Method == HttpMethod.Get)
        {
            return Json(new[] { agent });
        }

        if (path == "/v1/agents" && request.Method == HttpMethod.Post)
        {
            return Json(agent, HttpStatusCode.Created);
        }

        if (path == "/v1/runtime/evaluate")
        {
            var text = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(text);
            EvaluateCalls.Add(doc.RootElement.Clone());

            var tool = doc.RootElement.GetProperty("tool").GetString()!;
            var requestId = doc.RootElement.TryGetProperty("request_id", out var r)
                ? r.GetString()
                : "r";

            var response = new Dictionary<string, object?>
            {
                ["decision"] = "ALLOW",
                ["risk_score"] = 10,
                ["risk_severity"] = "low",
                ["request_id"] = requestId,
                ["reasons"] = Array.Empty<string>(),
                ["redactions"] = Array.Empty<string>(),
                ["fail_mode"] = "fail_closed",
                ["cache_hit"] = false,
                ["evaluated_in_ms"] = 1.0,
            };

            if (_decisions.TryGetValue(tool, out var overrides))
            {
                foreach (var kv in overrides)
                {
                    response[kv.Key] = kv.Value;
                }
            }

            return Json(response);
        }

        if (path.StartsWith("/v1/approvals/", StringComparison.Ordinal))
        {
            return Json(new { status = "approved" });
        }

        return Json(new { detail = "not found" }, HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };
    }
}
