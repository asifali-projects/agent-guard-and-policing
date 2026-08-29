using System.Text.Json.Serialization;

namespace AgentGuard;

/// <summary>Rate-limit envelope returned on a <c>RATE_LIMIT</c> decision.</summary>
public sealed record RateLimitInfo
{
    [JsonPropertyName("max")] public int Max { get; init; }
    [JsonPropertyName("window_seconds")] public int WindowSeconds { get; init; }
    [JsonPropertyName("scope")] public string Scope { get; init; } = "";
    [JsonPropertyName("remaining")] public int? Remaining { get; init; }
    [JsonPropertyName("retry_after_seconds")] public int? RetryAfterSeconds { get; init; }
}

/// <summary>The decision object returned by <c>POST /v1/runtime/evaluate</c> (PRD §24, §42).</summary>
public sealed record DecisionResult
{
    public required Decision Decision { get; init; }
    public int RiskScore { get; init; }
    public string RiskSeverity { get; init; } = "info";
    public string RequestId { get; init; } = "";
    public string? PolicyId { get; init; }
    public IReadOnlyList<string> PolicyKeys { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Redactions { get; init; } = Array.Empty<string>();
    public string? DataClassification { get; init; }
    public string? ApprovalRequestId { get; init; }
    public RateLimitInfo? RateLimit { get; init; }
    public string FailMode { get; init; } = "fail_closed";
    public bool CacheHit { get; init; }
    public double EvaluatedInMs { get; init; }

    /// <summary>True only for an <see cref="Decision.Allow"/> decision.</summary>
    public bool Allowed => Decision == Decision.Allow;

    internal static DecisionResult FromApi(RuntimeResponse r) => new()
    {
        Decision = DecisionParser.Parse(r.Decision),
        RiskScore = r.RiskScore,
        RiskSeverity = r.RiskSeverity,
        RequestId = r.RequestId,
        PolicyId = r.PolicyId,
        PolicyKeys = r.PolicyKeys,
        Reasons = r.Reasons,
        Redactions = r.Redactions,
        DataClassification = r.DataClassification,
        ApprovalRequestId = r.ApprovalRequestId,
        RateLimit = r.RateLimit,
        FailMode = r.FailMode,
        CacheHit = r.CacheHit,
        EvaluatedInMs = r.EvaluatedInMs,
    };

    internal static DecisionResult Unavailable(string reason) => new()
    {
        Decision = Decision.Deny,
        RiskScore = 100,
        RiskSeverity = "critical",
        Reasons = new[] { $"runtime unavailable: {reason}" },
        FailMode = "fail_closed",
    };
}

internal sealed record RuntimeResponse
{
    [JsonPropertyName("decision")] public string Decision { get; init; } = "DENY";
    [JsonPropertyName("risk_score")] public int RiskScore { get; init; }
    [JsonPropertyName("risk_severity")] public string RiskSeverity { get; init; } = "info";
    [JsonPropertyName("request_id")] public string RequestId { get; init; } = "";
    [JsonPropertyName("policy_id")] public string? PolicyId { get; init; }
    [JsonPropertyName("policy_keys")] public List<string> PolicyKeys { get; init; } = new();
    [JsonPropertyName("reasons")] public List<string> Reasons { get; init; } = new();
    [JsonPropertyName("redactions")] public List<string> Redactions { get; init; } = new();
    [JsonPropertyName("data_classification")] public string? DataClassification { get; init; }
    [JsonPropertyName("approval_request_id")] public string? ApprovalRequestId { get; init; }
    [JsonPropertyName("rate_limit")] public RateLimitInfo? RateLimit { get; init; }
    [JsonPropertyName("fail_mode")] public string FailMode { get; init; } = "fail_closed";
    [JsonPropertyName("cache_hit")] public bool CacheHit { get; init; }
    [JsonPropertyName("evaluated_in_ms")] public double EvaluatedInMs { get; init; }
}
