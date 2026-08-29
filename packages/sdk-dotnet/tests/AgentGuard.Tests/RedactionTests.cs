using System.Text.Json.Nodes;

using Xunit;

namespace AgentGuard.Tests;

public sealed class RedactionTests
{
    private static JsonObject Parse(string json) => (JsonObject)JsonNode.Parse(json)!;

    [Fact]
    public void Masks_a_top_level_leaf()
    {
        var output = Redaction.Apply(Parse("""{"to":"a","body":"secret"}"""), new[] { "parameters.body" });
        Assert.Equal("a", output["to"]!.GetValue<string>());
        Assert.Equal(Redaction.Redacted, output["body"]!.GetValue<string>());
    }

    [Fact]
    public void Masks_a_nested_leaf_and_leaves_siblings_intact()
    {
        var output = Redaction.Apply(
            Parse("""{"user":{"name":"Dana","email":"dana@x.com"}}"""),
            new[] { "parameters.user.email" });

        Assert.Equal("Dana", output["user"]!["name"]!.GetValue<string>());
        Assert.Equal(Redaction.Redacted, output["user"]!["email"]!.GetValue<string>());
    }

    [Fact]
    public void Masks_an_array_element_by_index()
    {
        var output = Redaction.Apply(
            Parse("""{"contacts":[{"email":"a@x.com"},{"email":"b@x.com"}]}"""),
            new[] { "parameters.contacts[1].email" });

        Assert.Equal("a@x.com", output["contacts"]![0]!["email"]!.GetValue<string>());
        Assert.Equal(Redaction.Redacted, output["contacts"]![1]!["email"]!.GetValue<string>());
    }

    [Fact]
    public void Does_not_mutate_the_input()
    {
        var input = Parse("""{"body":"secret"}""");
        Redaction.Apply(input, new[] { "parameters.body" });
        Assert.Equal("secret", input["body"]!.GetValue<string>());
    }

    [Fact]
    public void Ignores_paths_that_do_not_resolve()
    {
        var output = Redaction.Apply(Parse("""{"a":1}"""), new[] { "parameters.b.c", "parameters.a.deep" });
        Assert.Equal(1, output["a"]!.GetValue<int>());
    }

    [Fact]
    public void Accepts_paths_without_the_parameters_prefix()
    {
        var output = Redaction.Apply(Parse("""{"x":"y"}"""), new[] { "x" });
        Assert.Equal(Redaction.Redacted, output["x"]!.GetValue<string>());
    }
}
