using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentGuard;

/// <summary>
/// The AgentGuard facade — identity resolution, tool enforcement, and raw
/// control-plane access (PRD §37).
/// </summary>
/// <example>
/// <code>
/// using var guard = new AgentGuardClient(new AgentGuardOptions
/// {
///     ApiKey = "ag_live_...", Agent = "FinanceAgent", Environment = "production",
/// });
///
/// await guard.GuardAsync("send_email", new { to, subject, body }, async (effective, ct) =>
/// {
///     // runs only on ALLOW / REDACT; `effective` is the masked copy on REDACT
/// });
/// </code>
/// </example>
public sealed class AgentGuardClient : IDisposable
{
    private readonly RuntimeApi _api;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private string? _agentId;

    public AgentGuardClient(AgentGuardOptions options, HttpClient? httpClient = null)
    {
        Options = options ?? throw new ArgumentNullException(nameof(options));
        options.EnsureApiKey();
        _http = httpClient ?? new HttpClient();
        _ownsHttp = httpClient is null;
        _api = new RuntimeApi(_http, options);
        Api = new ControlPlaneApi(_api);
    }

    public AgentGuardOptions Options { get; }

    /// <summary>Raw, typed access to the control-plane REST API.</summary>
    public ControlPlaneApi Api { get; }

    /// <summary>Pre-set the agent id, skipping the identity lookup.</summary>
    public void SetAgentId(string id) => _agentId = id;

    /// <summary>Resolve (and, if needed, register) the configured agent's id.</summary>
    public async Task<string> GetAgentIdAsync(CancellationToken cancellationToken = default)
    {
        if (_agentId is null)
        {
            if (string.IsNullOrEmpty(Options.Agent))
            {
                throw new ConfigurationException(
                    "no agent — set Options.Agent or AGENTGUARD_AGENT");
            }

            _agentId = await _api
                .ResolveAgentIdAsync(Options.Agent!, Options.Environment, cancellationToken)
                .ConfigureAwait(false);
        }

        return _agentId;
    }

    /// <summary>
    /// Ask the runtime what to do. Returns a decision; only throws
    /// <see cref="RuntimeUnavailableException"/> when <see cref="FailMode.Closed"/>
    /// and the API is unreachable.
    /// </summary>
    public async Task<DecisionResult> EvaluateAsync(
        string tool,
        object? parameters = null,
        EvaluateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new EvaluateOptions();
        var requestId = options.RequestId ?? Guid.NewGuid().ToString("N");
        var body = new EvaluateRequestBody
        {
            AgentId = await GetAgentIdAsync(cancellationToken).ConfigureAwait(false),
            Tool = tool,
            Action = options.Action,
            Parameters = ToNode(parameters),
            Context = options.Context is null ? new JsonObject() : ToNode(options.Context),
            RequestId = requestId,
            DataClassification = options.DataClassification,
        };

        try
        {
            return await _api.EvaluateAsync(body, cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeUnavailableException) when (Options.FailMode == FailMode.Open)
        {
            return DecisionResult.Unavailable("fail-open") with
            {
                Decision = Decision.Allow,
                RiskScore = 0,
                RiskSeverity = "info",
                Reasons = new[] { "runtime unavailable — fail-open" },
                FailMode = "fail_open",
                RequestId = requestId,
            };
        }
    }

    /// <summary>
    /// Evaluate and enforce. Returns the decision plus the effective parameters
    /// (a masked copy on <c>REDACT</c>); throws otherwise.
    /// </summary>
    public async Task<CheckResult> CheckAsync(
        string tool,
        object? parameters = null,
        EvaluateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var incoming = ToObject(parameters);

        DecisionResult result;
        try
        {
            result = await EvaluateAsync(tool, parameters, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (RuntimeUnavailableException ex)
        {
            throw new PolicyDeniedException(
                $"runtime unavailable (fail-closed): {ex.Message}",
                DecisionResult.Unavailable(ex.Message));
        }

        return result.Decision switch
        {
            Decision.Allow => new CheckResult(result, incoming),
            Decision.Redact => new CheckResult(result, Redaction.Apply(incoming, result.Redactions)),
            Decision.Approval => throw new ApprovalRequiredException(
                Join(result.Reasons, "approval required"), result),
            Decision.RateLimit => throw new RateLimitedException(
                Join(result.Reasons, "rate limited"), result),
            _ => throw new PolicyDeniedException(Join(result.Reasons, "denied"), result),
        };
    }

    /// <summary>Enforce, then run <paramref name="invoke"/> with the effective parameters.</summary>
    public async Task<T> GuardAsync<T>(
        string tool,
        object? parameters,
        Func<JsonObject, CancellationToken, Task<T>> invoke,
        EvaluateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var check = await CheckAsync(tool, parameters, options, cancellationToken).ConfigureAwait(false);
        return await invoke(check.Parameters, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Enforce, then run <paramref name="invoke"/> with the effective parameters.</summary>
    public async Task GuardAsync(
        string tool,
        object? parameters,
        Func<JsonObject, CancellationToken, Task> invoke,
        EvaluateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var check = await CheckAsync(tool, parameters, options, cancellationToken).ConfigureAwait(false);
        await invoke(check.Parameters, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Block until an approval request is decided. Returns its final status.</summary>
    public async Task<string> WaitForApprovalAsync(
        string approvalRequestId,
        TimeSpan? pollInterval = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var interval = pollInterval ?? TimeSpan.FromSeconds(2);
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromMinutes(5));
        while (DateTime.UtcNow < deadline)
        {
            var row = await _api
                .GetAsync($"/v1/approvals/{approvalRequestId}", null, cancellationToken)
                .ConfigureAwait(false);
            var status = row.GetProperty("status").GetString();
            if (status != "pending")
            {
                return status ?? "unknown";
            }

            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
        }

        return "timeout";
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private static string Join(IReadOnlyList<string> reasons, string fallback) =>
        reasons.Count > 0 ? string.Join("; ", reasons) : fallback;

    private static JsonObject ToObject(object? parameters)
    {
        var node = ToNode(parameters);
        return node as JsonObject
            ?? throw new ArgumentException("parameters must serialise to a JSON object", nameof(parameters));
    }

    private static JsonNode ToNode(object? value)
    {
        return value switch
        {
            null => new JsonObject(),
            JsonObject obj => (JsonNode)obj.DeepClone(),
            _ => JsonSerializer.SerializeToNode(value, JsonOptions.Web) ?? new JsonObject(),
        };
    }
}

/// <summary>The decision plus the parameters to actually call the tool with.</summary>
public sealed record CheckResult(DecisionResult Result, JsonObject Parameters);

/// <summary>Per-call options for <see cref="AgentGuardClient.EvaluateAsync"/> / CheckAsync.</summary>
public sealed class EvaluateOptions
{
    public string Action { get; set; } = "execute";
    public IReadOnlyDictionary<string, object?>? Context { get; set; }
    public string? RequestId { get; set; }
    public string? DataClassification { get; set; }
}

/// <summary>Typed pass-through to the control-plane REST API.</summary>
public sealed class ControlPlaneApi
{
    private readonly RuntimeApi _api;

    internal ControlPlaneApi(RuntimeApi api) => _api = api;

    public Task<JsonElement> GetAsync(
        string path,
        IReadOnlyDictionary<string, string?>? query = null,
        CancellationToken cancellationToken = default) => _api.GetAsync(path, query, cancellationToken);

    public Task<JsonElement> PostAsync(
        string path,
        object? body = null,
        CancellationToken cancellationToken = default) => _api.PostAsync(path, body, cancellationToken);

    public Task<string> ResolveAgentIdAsync(
        string name,
        string environment,
        CancellationToken cancellationToken = default) =>
        _api.ResolveAgentIdAsync(name, environment, cancellationToken);
}
