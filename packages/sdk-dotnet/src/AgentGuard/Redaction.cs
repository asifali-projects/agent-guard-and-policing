using System.Text.RegularExpressions;
using System.Text.Json.Nodes;

namespace AgentGuard;

/// <summary>Applies the runtime's redaction paths to a parameter object.</summary>
public static partial class Redaction
{
    public const string Redacted = "[REDACTED]";

    [GeneratedRegex(@"\[(\d+)\]")]
    private static partial Regex IndexPattern();

    /// <summary>
    /// Return a deep copy of <paramref name="parameters"/> with every
    /// <paramref name="paths"/> leaf masked. Paths look like
    /// <c>parameters.user.contacts[0].email</c>.
    /// </summary>
    public static JsonObject Apply(JsonObject parameters, IEnumerable<string> paths)
    {
        var result = (JsonObject)parameters.DeepClone();
        foreach (var path in paths)
        {
            var tokens = Tokenize(path);
            if (tokens.Count == 0)
            {
                continue;
            }

            JsonNode? node = result;
            for (var i = 0; i < tokens.Count - 1 && node is not null; i++)
            {
                node = Descend(node, tokens[i]);
            }

            if (node is not null)
            {
                Assign(node, tokens[^1], Redacted);
            }
        }

        return result;
    }

    private static List<object> Tokenize(string path)
    {
        var body = path.StartsWith("parameters.", StringComparison.Ordinal)
            ? path["parameters.".Length..]
            : path;
        var tokens = new List<object>();
        foreach (var part in body.Split('.'))
        {
            var match = IndexPattern().Match(part);
            var name = IndexPattern().Replace(part, string.Empty);
            if (name.Length > 0)
            {
                tokens.Add(name);
            }

            if (match.Success)
            {
                tokens.Add(int.Parse(match.Groups[1].Value));
            }
        }

        return tokens;
    }

    private static JsonNode? Descend(JsonNode node, object key) => key switch
    {
        string name when node is JsonObject obj => obj.TryGetPropertyValue(name, out var v) ? v : null,
        int index when node is JsonArray arr && index >= 0 && index < arr.Count => arr[index],
        _ => null,
    };

    private static void Assign(JsonNode node, object key, string value)
    {
        switch (key)
        {
            case string name when node is JsonObject obj && obj.ContainsKey(name):
                obj[name] = value;
                break;
            case int index when node is JsonArray arr && index >= 0 && index < arr.Count:
                arr[index] = value;
                break;
        }
    }
}
