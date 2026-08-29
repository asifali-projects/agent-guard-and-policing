namespace AgentGuard;

/// <summary>Policy decision engine output (PRD §24).</summary>
public enum Decision
{
    Allow,
    Deny,
    Approval,
    Redact,
    RateLimit,
}

/// <summary>Behaviour when the runtime API is unreachable (PRD §59).</summary>
public enum FailMode
{
    Closed,
    Open,
}

internal static class DecisionParser
{
    public static Decision Parse(string? value) => value?.ToUpperInvariant() switch
    {
        "ALLOW" => Decision.Allow,
        "APPROVAL" => Decision.Approval,
        "REDACT" => Decision.Redact,
        "RATE_LIMIT" => Decision.RateLimit,
        _ => Decision.Deny,
    };
}
