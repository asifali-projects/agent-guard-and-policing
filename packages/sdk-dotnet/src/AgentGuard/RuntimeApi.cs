using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace AgentGuard;

/// <summary>Thin HTTP wrapper for the AgentGuard runtime + control-plane API.</summary>
internal sealed class RuntimeApi
{
    private const string UserAgent = "agentguard-dotnet/0.0.0";

    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private readonly TimeSpan _timeout;

    public RuntimeApi(HttpClient http, AgentGuardOptions options)
    {
        _http = http;
        _baseUrl = options.NormalisedBaseUrl;
        _apiKey = options.ApiKey!;
        _timeout = options.Timeout;
    }

    public async Task<DecisionResult> EvaluateAsync(EvaluateRequestBody body, CancellationToken ct)
    {
        using var resp = await SendAsync(HttpMethod.Post, "/v1/runtime/evaluate", body, null, ct)
            .ConfigureAwait(false);
        var parsed = await ReadJsonAsync<RuntimeResponse>(resp, ct).ConfigureAwait(false);
        return DecisionResult.FromApi(parsed ?? new RuntimeResponse());
    }

    public async Task<JsonElement> GetAsync(
        string path, IReadOnlyDictionary<string, string?>? query = null, CancellationToken ct = default)
    {
        using var resp = await SendAsync(HttpMethod.Get, path, null, query, ct).ConfigureAwait(false);
        return await ReadElementAsync(resp, ct).ConfigureAwait(false);
    }

    public async Task<JsonElement> PostAsync(
        string path, object? body = null, CancellationToken ct = default)
    {
        using var resp = await SendAsync(HttpMethod.Post, path, body, null, ct).ConfigureAwait(false);
        return await ReadElementAsync(resp, ct).ConfigureAwait(false);
    }

    public async Task<string> ResolveAgentIdAsync(
        string name, string environment, CancellationToken ct = default)
    {
        var agents = await GetAsync("/v1/agents", null, ct).ConfigureAwait(false);
        foreach (var agent in agents.EnumerateArray())
        {
            if (agent.GetProperty("name").GetString() == name
                && agent.GetProperty("environment").GetString() == environment)
            {
                return agent.GetProperty("id").GetString()!;
            }
        }

        var created = await PostAsync(
            "/v1/agents", new { name, environment }, ct).ConfigureAwait(false);
        return created.GetProperty("id").GetString()!;
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        IReadOnlyDictionary<string, string?>? query,
        CancellationToken ct)
    {
        var url = _baseUrl + path;
        if (query is not null)
        {
            var pairs = query
                .Where(kv => !string.IsNullOrEmpty(kv.Value))
                .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}");
            var qs = string.Join("&", pairs);
            if (qs.Length > 0)
            {
                url += "?" + qs;
            }
        }

        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {_apiKey}");
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: JsonOptions.Web);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        try
        {
            return await _http.SendAsync(request, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException
            || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            throw new RuntimeUnavailableException($"{method} {path} failed: {ex.Message}", ex);
        }
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpResponseMessage resp, CancellationToken ct)
    {
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return string.IsNullOrEmpty(text)
            ? default
            : JsonSerializer.Deserialize<T>(text, JsonOptions.Web);
    }

    private static async Task<JsonElement> ReadElementAsync(
        HttpResponseMessage resp, CancellationToken ct)
    {
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(text))
        {
            return default;
        }

        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode)
        {
            return;
        }

        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var detail = text;
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("detail", out var d))
            {
                detail = d.ToString();
            }
        }
        catch (JsonException)
        {
            // keep the raw body
        }

        throw new AgentGuardException($"HTTP {(int)resp.StatusCode}: {detail}");
    }
}

internal sealed record EvaluateRequestBody
{
    [JsonPropertyName("agent_id")] public required string AgentId { get; init; }
    [JsonPropertyName("tool")] public required string Tool { get; init; }
    [JsonPropertyName("action")] public string Action { get; init; } = "execute";
    [JsonPropertyName("parameters")] public JsonNode Parameters { get; init; } = new JsonObject();
    [JsonPropertyName("context")] public JsonNode Context { get; init; } = new JsonObject();
    [JsonPropertyName("request_id")] public string? RequestId { get; init; }
    [JsonPropertyName("data_classification")] public string? DataClassification { get; init; }
}
