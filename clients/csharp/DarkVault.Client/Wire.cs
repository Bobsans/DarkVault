using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jose;

namespace DarkVault.Client;

public static class Wire {
    public const int MaxBody = 2 * 1024 * 1024;
    public const int MaxPlaintext = 1536 * 1024;
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) {
        MaxDepth = 16,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        Converters = { new UtcDateConverter() }
    };
    public static readonly JsonSerializerOptions ResponseJson = new(Json) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip };
    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);
    public static T Parse<T>(string json) {
        ValidateJson(json);
        return JsonSerializer.Deserialize<T>(json, Json) ?? throw new FormatException("Missing JSON value.");
    }
    public static void ValidateJson(string json) {
        if (Encoding.UTF8.GetByteCount(json) > MaxPlaintext) throw new InvalidDataException("Payload too large.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
        Check(doc.RootElement);
        static void Check(JsonElement node) {
            if (node.ValueKind == JsonValueKind.Object) {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in node.EnumerateObject()) {
                    if (!names.Add(p.Name)) throw new FormatException("Duplicate JSON field.");
                    Check(p.Value);
                }
            } else if (node.ValueKind == JsonValueKind.Array) foreach (var v in node.EnumerateArray()) Check(v);
        }
    }
    public static string Base64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] Unbase64(string text) {
        if (text.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')) throw new FormatException("Invalid base64url.");
        var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
        if (Base64(bytes) != text) throw new FormatException("Noncanonical base64url.");
        return bytes;
    }
    public static string HashToken(string token) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    public static bool IsToken(string token) => token.Length == 64 && token.StartsWith("dv1_", StringComparison.Ordinal)
        && token.AsSpan(4).ToArray().All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    public static string NewToken() => "dv1_" + Base64(RandomNumberGenerator.GetBytes(45));
    public static PublicKey Export(ECDsa key) {
        var p = key.ExportParameters(false);
        return new("EC", "P-256", Base64(p.Q.X!), Base64(p.Q.Y!));
    }
    public static ECDsa Import(PublicKey key) {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Kty != "EC" || key.Crv != "P-256") throw new FormatException("Invalid key type.");
        var x = Unbase64(key.X); var y = Unbase64(key.Y);
        if (x.Length != 32 || y.Length != 32) throw new FormatException("Invalid coordinates.");
        return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
    }
    public static string Encrypt(string json, PublicKey key, string kid, string type) {
        ValidateJson(json);
        using var ec = Import(key);
        var result = JWT.Encode(json, ec, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM,
            extraHeaders: new Dictionary<string, object> { ["kid"] = kid, ["typ"] = type, ["cty"] = "application/json" });
        if (result.Length > MaxBody) throw new FormatException("Payload too large.");
        return result;
    }
    public static string Header(string compact, string type) {
        if (compact.Length > MaxBody) throw new InvalidDataException("Payload too large.");
        var parts = compact.Split('.');
        if (parts.Length != 5 || parts[1] != "" || parts[0].Length > 4096) throw new FormatException("Invalid envelope.");
        var header = Encoding.UTF8.GetString(Unbase64(parts[0]));
        ValidateJson(header);
        using var doc = JsonDocument.Parse(header);
        var h = doc.RootElement;
        string[] fields = ["alg", "enc", "epk", "kid", "typ", "cty"];
        if (h.EnumerateObject().Count() != fields.Length || h.EnumerateObject().Any(p => !fields.Contains(p.Name)) ||
            h.GetProperty("alg").GetString() != "ECDH-ES" || h.GetProperty("enc").GetString() != "A256GCM" ||
            h.GetProperty("typ").GetString() != type || h.GetProperty("cty").GetString() != "application/json" ||
            Unbase64(parts[2]).Length != 12 || Unbase64(parts[4]).Length != 16) throw new FormatException("Invalid envelope.");
        using var epk = Import(Parse<PublicKey>(h.GetProperty("epk").GetRawText()));
        _ = Unbase64(parts[3]);
        return h.GetProperty("kid").GetString() ?? throw new FormatException("Missing key ID.");
    }
    public static string Decrypt(string compact, ECDsa key, string kid, string type) {
        if (Header(compact, type) != kid) throw new FormatException("Unexpected key ID.");
        var json = JWT.Decode(compact, key, JweAlgorithm.ECDH_ES, JweEncryption.A256GCM);
        ValidateJson(json);
        return json;
    }
    public static async Task<string> ReadBodyAsync(Stream stream, CancellationToken ct) {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(chunk, ct)) != 0) {
            if (buffer.Length + n > MaxBody) throw new InvalidDataException("Payload too large.");
            buffer.Write(chunk, 0, n);
        }
        return new UTF8Encoding(false, true).GetString(buffer.ToArray());
    }
    private sealed class UtcDateConverter : JsonConverter<DateTimeOffset> {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) => reader.GetDateTimeOffset();
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) => writer.WriteStringValue(value.UtcDateTime);
    }
}

public sealed record PublicKey(string Kty, string Crv, string X, string Y);
public sealed record CryptoKey(int ProtocolVersion, string ServerId, DateTimeOffset ServerTime, string Kid, PublicKey PublicKey, DateTimeOffset NotAfter, object? Limits = null);
public sealed record VaultRequest(int V, string RequestId, DateTimeOffset IssuedAt, string ServerId, string Audience, string Operation, JsonElement Parameters, PublicKey ReplyKey);
public sealed record VaultError(string Code, string Message);
public sealed record VaultResponse(int V, string RequestId, string ServerId, string Audience, string Operation, int Status, JsonElement? Data, VaultError? Error);
public sealed record Bucket(string Id, string Name, string Description, long Revision, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);
public sealed record SecretMetadata(string Id, string BucketId, string Key, long Revision, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);
public sealed record Secret(string Id, string BucketId, string Key, long Revision, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, string Value);
public sealed record BucketSnapshot(string BucketId, long Revision, Dictionary<string, string?> Secrets);
public sealed record Page<T>(IReadOnlyList<T> Items, string? NextCursor);
public sealed record TokenInfo(string Id, string Name, string[] Scopes, string[] BucketIds, bool AllBuckets, string[] CreatableBucketNames, DateTimeOffset? ExpiresAt);
public sealed class DarkVaultException(string code, int status, string? requestId = null) : Exception($"DarkVault request failed ({code}).") {
    public string Code { get; } = code;
    public int Status { get; } = status;
    public string? RequestId { get; } = requestId;
}
