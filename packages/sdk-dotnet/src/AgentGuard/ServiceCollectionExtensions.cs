using Microsoft.Extensions.DependencyInjection;

namespace AgentGuard;

/// <summary>DI wiring for ASP.NET Core / generic-host applications.</summary>
public static class AgentGuardServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="AgentGuardClient"/> and its <see cref="AgentGuardOptions"/> as
    /// singletons. Options start from the environment / config file; the callback overrides.
    /// </summary>
    public static IServiceCollection AddAgentGuard(
        this IServiceCollection services, Action<AgentGuardOptions>? configure = null)
    {
        var options = AgentGuardOptions.FromEnvironment();
        configure?.Invoke(options);
        options.EnsureApiKey();

        services.AddSingleton(options);
        services.AddSingleton(sp => new AgentGuardClient(sp.GetRequiredService<AgentGuardOptions>()));
        return services;
    }
}
