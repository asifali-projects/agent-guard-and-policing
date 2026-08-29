namespace AgentGuard;

/// <summary>Base class for every AgentGuard SDK error.</summary>
public class AgentGuardException : Exception
{
    public AgentGuardException(string message) : base(message) { }
    public AgentGuardException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Missing or invalid configuration (API key, base URL, agent).</summary>
public sealed class ConfigurationException : AgentGuardException
{
    public ConfigurationException(string message) : base(message) { }
}

/// <summary>The runtime API could not be reached. Fail-safe behaviour applies.</summary>
public sealed class RuntimeUnavailableException : AgentGuardException
{
    public RuntimeUnavailableException(string message) : base(message) { }
    public RuntimeUnavailableException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Base for decisions that prevent the tool call. Carries the full result.</summary>
public class BlockedException : AgentGuardException
{
    public DecisionResult Result { get; }

    public BlockedException(string message, DecisionResult result) : base(message)
    {
        Result = result;
    }
}

/// <summary>The action was denied (policy, DLP block, or critical risk).</summary>
public sealed class PolicyDeniedException : BlockedException
{
    public PolicyDeniedException(string message, DecisionResult result) : base(message, result) { }
}

/// <summary>A human must approve this exact action before it can proceed.</summary>
public sealed class ApprovalRequiredException : BlockedException
{
    public ApprovalRequiredException(string message, DecisionResult result) : base(message, result) { }

    public string? ApprovalRequestId => Result.ApprovalRequestId;
}

/// <summary>The action exceeded its rate-limit budget.</summary>
public sealed class RateLimitedException : BlockedException
{
    public RateLimitedException(string message, DecisionResult result) : base(message, result) { }

    public int? RetryAfterSeconds => Result.RateLimit?.RetryAfterSeconds;
}
