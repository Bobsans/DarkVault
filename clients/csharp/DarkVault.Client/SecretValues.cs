using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DarkVault.Client;

public static class SecretValues {
    public static string Normalize(string value, string type) {
        if (type == "string") return value;
        try {
            using var document = JsonDocument.Parse(value);
            var element = document.RootElement;
            if (type == "boolean" && element.ValueKind is JsonValueKind.True or JsonValueKind.False) return element.GetBoolean() ? "true" : "false";
            if (type == "null" && element.ValueKind == JsonValueKind.Null) return "null";
            if (type == "number" && element.ValueKind == JsonValueKind.Number && element.TryGetDouble(out var number)
                && double.IsFinite(number) && (Math.Truncate(number) != number || Math.Abs(number) <= 9007199254740991))
                return number == 0 ? "0" : number.ToString("R", CultureInfo.InvariantCulture);
        } catch (JsonException) { }
        throw new ArgumentException("Invalid secret type or scalar value.");
    }
    public static JsonElement Parse(string value, string type = "string") {
        if (type == "string") return JsonSerializer.SerializeToElement(value, Wire.TypeInfo<string>());
        using var document = JsonDocument.Parse(Normalize(value, type)); return document.RootElement.Clone();
    }
    public static (string Value, string Type) Encode(JsonElement value) {
        var type = value.ValueKind switch {
            JsonValueKind.String => "string",
            JsonValueKind.Number => "number",
            JsonValueKind.True or JsonValueKind.False => "boolean",
            JsonValueKind.Null => "null",
            _ => throw new ArgumentException("Secret values must be JSON scalars.")
        };
        return (Normalize(type == "string" ? value.GetString()! : value.GetRawText(), type), type);
    }
    public static void ValidateConfigurationPaths(IEnumerable<string> keys) {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var leaves = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in keys) {
            var parts = Path(key); var prefix = new System.Text.StringBuilder();
            for (var i = 0; i < parts.Length; i++) {
                if (i > 0) prefix.Append(':');
                prefix.Append(parts[i]); var current = prefix.ToString();
                if (i < parts.Length - 1) {
                    if (leaves.Contains(current)) throw new ArgumentException("Configuration paths conflict.");
                    paths.Add(current);
                } else {
                    if (!paths.Add(current)) throw new ArgumentException("Configuration paths conflict.");
                    leaves.Add(current);
                }
            }
        }
    }
    public static Dictionary<string, JsonElement> Typed(BucketSnapshot snapshot) {
        if (snapshot.Secrets.Any(p => p.Value is null) || snapshot.Types.Keys.Any(k => !snapshot.Secrets.ContainsKey(k)))
            throw new FormatException("Invalid secret type map.");
        return snapshot.Secrets.ToDictionary(p => p.Key, p => Parse(p.Value!, snapshot.Types.GetValueOrDefault(p.Key) ?? "string"), StringComparer.Ordinal);
    }
    public static JsonObject Configuration(IReadOnlyDictionary<string, JsonElement> values, bool nested = true) {
        if (nested) ValidateConfigurationPaths(values.Keys);
        var root = new JsonObject();
        foreach (var (key, value) in values) {
            _ = Encode(value);
            var path = nested ? Path(key) : [key]; var parent = root;
            for (var i = 0; i < path.Length - 1; i++) {
                if (!parent.ContainsKey(path[i])) parent[path[i]] = new JsonObject();
                if (parent[path[i]] is not JsonObject child) throw new ArgumentException("Configuration paths conflict.");
                parent = child;
            }
            if (parent.ContainsKey(path[^1])) throw new ArgumentException("Configuration paths conflict.");
            parent[path[^1]] = JsonNode.Parse(value.GetRawText());
        }
        return root;
    }
    private static string[] Path(string key) {
        var parts = new List<string>(); var part = new System.Text.StringBuilder(); var escaped = false;
        foreach (var ch in key) {
            if (escaped) { if (ch is not (':' or '\\')) throw new ArgumentException("Invalid configuration path escape."); part.Append(ch); escaped = false; } else if (ch == '\\') escaped = true;
            else if (ch == ':') { parts.Add(part.ToString()); part.Clear(); } else part.Append(ch);
        }
        parts.Add(part.ToString());
        if (escaped || parts.Count > 16 || parts.Any(p => p.Length == 0)) throw new ArgumentException("Invalid configuration path.");
        return parts.ToArray();
    }
}
