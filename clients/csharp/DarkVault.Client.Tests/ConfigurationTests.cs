using System.Text.Json;
using DarkVault.Client;
using NUnit.Framework;

namespace DarkVault.Client.Tests;

public sealed class ConfigurationTests {
    [Test]
    public void ScalarsPathsAndConflictsAreExplicit() {
        Assert.That(SecretValues.Parse("00123").GetString(), Is.EqualTo("00123"));
        Assert.That(SecretValues.Parse("1e2", "number").GetDouble(), Is.EqualTo(100));
        Assert.That(SecretValues.Parse("false", "boolean").GetBoolean(), Is.False);
        Assert.That(SecretValues.Parse("null", "null").ValueKind, Is.EqualTo(JsonValueKind.Null));
        foreach (var (value, type) in new[] { ("NaN", "number"), ("1e999", "number"), ("9007199254740992", "number"), ("01", "number"), ("true", "number"), ("1", "boolean"), ("", "null"), ("{}", "object") })
            Assert.Throws<ArgumentException>(() => SecretValues.Parse(value, type));
        var values = new Dictionary<string, JsonElement> { ["Redis:Port"] = SecretValues.Parse("6379", "number"), ["Redis:Enabled"] = SecretValues.Parse("true", "boolean"), ["Literal\\:Key"] = SecretValues.Parse("null"), ["Years:2026"] = SecretValues.Parse("value"), ["Empty"] = SecretValues.Parse("null", "null") };
        var tree = SecretValues.Configuration(values);
        Assert.That(tree["Redis"]!["Port"]!.GetValue<double>(), Is.EqualTo(6379));
        Assert.That(tree["Redis"]!["Enabled"]!.GetValue<bool>(), Is.True);
        Assert.That(tree["Literal:Key"]!.GetValue<string>(), Is.EqualTo("null"));
        Assert.That(tree["Years"]!["2026"]!.GetValue<string>(), Is.EqualTo("value"));
        Assert.That(tree.ContainsKey("Empty"), Is.True); Assert.That(tree["Empty"], Is.Null);
        values["Redis"] = SecretValues.Parse("conflict"); Assert.Throws<ArgumentException>(() => SecretValues.Configuration(values));
        Assert.Throws<ArgumentException>(() => SecretValues.Configuration(new Dictionary<string, JsonElement> { ["Redis"] = SecretValues.Parse("x"), ["redis:Port"] = SecretValues.Parse("1") }));
        Assert.That(SecretValues.Configuration(values, false).ContainsKey("Redis:Port"), Is.True);
        foreach (var path in new[] { "A::B", "A:", ":A", "A\\x", "A\\", string.Join(":", Enumerable.Repeat("a", 17)) })
            Assert.Throws<ArgumentException>(() => SecretValues.Configuration(new Dictionary<string, JsonElement> { [path] = SecretValues.Parse("x") }));
    }
}
