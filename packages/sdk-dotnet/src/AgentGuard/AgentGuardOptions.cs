using System.Text.Json;

namespace AgentGuard;

/// <summary>
/// SDK configuration. Resolution order per field: explicit value → environment
/// variable → <c>~/.agentguard/config.json</c> → default.
/// </summary>
public sealed class AgentGuardOptions
{
    public const string DefaultBaseUrl = "http://localhost:8010";

    public string? ApiKey { get; set; }
    public string BaseUrl { get; set; } = DefaultBaseUrl;
    public string? Agent { get; set; }
    public string Environment { get; set; } = "production";
    public FailMode FailMode { get; set; } = FailMode.Closed;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
    public bool AutoRegister { get; set; } = true;

    /// <summary>The base URL without a trailing slash.</summary>
    public string NormalisedBaseUrl => BaseUrl.TrimEnd('/');

    internal void EnsureApiKey()
    {
        if (string.IsNullOrEmpty(ApiKey))
        {
            throw new ConfigurationException(
                "no API key — set Options.ApiKey, AGENTGUARD_API_KEY, or run `agentguard login`");
        }
    }

    /// <summary>Build options from environment variables and the config file.</summary>
    public static AgentGuardOptions FromEnvironment()
    {
        var file = LoadConfigFile();
        string? Env(string key) => System.Environment.GetEnvironmentVariable(key);
        string? Pick(string envKey, string fileKey) =>
            Env(envKey) ?? (file.TryGetValue(fileKey, out var v) ? v : null);

        var options = new AgentGuardOptions
        {
            ApiKey = Pick("AGENTGUARD_API_KEY", "api_key"),
            BaseUrl = Pick("AGENTGUARD_BASE_URL", "base_url") ?? DefaultBaseUrl,
            Agent = Pick("AGENTGUARD_AGENT", "agent"),
            Environment = Pick("AGENTGUARD_ENVIRONMENT", "environment") ?? "production",
        };

        var failMode = Pick("AGENTGUARD_FAIL_MODE", "fail_mode");
        if (failMode is not null)
        {
            options.FailMode = failMode.ToLowerInvariant() switch
            {
                "open" => FailMode.Open,
                "closed" => FailMode.Closed,
                _ => throw new ConfigurationException("fail mode must be 'closed' or 'open'"),
            };
        }

        var timeout = Env("AGENTGUARD_TIMEOUT");
        if (timeout is not null && double.TryParse(timeout, out var seconds))
        {
            options.Timeout = TimeSpan.FromSeconds(seconds);
        }

        return options;
    }

    /// <summary>Path to the config file (<c>$AGENTGUARD_CONFIG</c> or the default).</summary>
    public static string ConfigPath()
    {
        var overridePath = System.Environment.GetEnvironmentVariable("AGENTGUARD_CONFIG");
        if (!string.IsNullOrEmpty(overridePath))
        {
            return overridePath;
        }

        var home = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".agentguard", "config.json");
    }

    internal static Dictionary<string, string> LoadConfigFile()
    {
        var path = ConfigPath();
        if (!File.Exists(path))
        {
            return new Dictionary<string, string>();
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var result = new Dictionary<string, string>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    result[prop.Name] = prop.Value.GetString()!;
                }
            }

            return result;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            throw new ConfigurationException($"could not read {path}: {ex.Message}");
        }
    }

    /// <summary>Persist credentials to the config file with owner-only permissions.</summary>
    public static string Save(IReadOnlyDictionary<string, string?> data)
    {
        var path = ConfigPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var clean = data
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => kv.Key, kv => kv.Value!);
        File.WriteAllText(path, JsonSerializer.Serialize(clean, JsonOptions.Indented) + "\n");

        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch (Exception ex) when (ex is IOException or PlatformNotSupportedException)
            {
                // best effort
            }
        }

        return path;
    }
}

internal static class JsonOptions
{
    public static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    public static readonly JsonSerializerOptions Indented = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };
}
