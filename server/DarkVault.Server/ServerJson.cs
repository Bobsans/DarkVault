using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using DarkVault.Client;

namespace DarkVault.Server;

internal static class ServerJson {
    private static readonly JsonSerializerOptions Options = new(Wire.Json) {
        TypeInfoResolver = JsonTypeInfoResolver.Combine(ServerJsonContext.Default, Wire.Json.TypeInfoResolver!)
    };
    public static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Options.GetTypeInfo(typeof(T));
    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, TypeInfo<T>());
    public static JsonElement ToElement(object value) => JsonSerializer.SerializeToElement(value, Options.GetTypeInfo(value.GetType()));
    public static T Parse<T>(string json) {
        Wire.ValidateJson(json);
        return JsonSerializer.Deserialize(json, TypeInfo<T>()) ?? throw new FormatException("Missing JSON value.");
    }
    public static Task Write<T>(HttpContext context, T value) => context.Response.WriteAsJsonAsync(value, TypeInfo<T>(), cancellationToken: context.RequestAborted);
}

internal sealed record TransportLimits(int MaxBodyBytes, int MaxPlaintextBytes);
internal sealed record HealthResult(string Status);
internal sealed record SessionResult(bool Authenticated, string? CsrfToken);
internal sealed record AuthenticationResult(bool Authenticated);
internal sealed record PasswordResult(bool Changed);
internal sealed record ErrorResult(VaultError Error);
internal sealed record DeleteResult(bool Deleted);
internal sealed record RevokeResult(bool Revoked);
internal sealed record TokenCreated(VaultStore.TokenRecord Metadata, string Token);
internal sealed record AuditEntry(DateTimeOffset Time, string Principal, string Operation, string? BucketId, string? SecretId, string RequestId, string Result);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(KeyRing.Ring))]
[JsonSerializable(typeof(VaultStore.Admin))]
[JsonSerializable(typeof(VaultStore.TokenRecord))]
[JsonSerializable(typeof(VaultStore.StoredSecret))]
[JsonSerializable(typeof(Page<VaultStore.TokenRecord>))]
[JsonSerializable(typeof(Page<JsonElement>))]
[JsonSerializable(typeof(TransportLimits))]
[JsonSerializable(typeof(HealthResult))]
[JsonSerializable(typeof(SessionResult))]
[JsonSerializable(typeof(AuthenticationResult))]
[JsonSerializable(typeof(PasswordResult))]
[JsonSerializable(typeof(ErrorResult))]
[JsonSerializable(typeof(DeleteResult))]
[JsonSerializable(typeof(RevokeResult))]
[JsonSerializable(typeof(TokenCreated))]
[JsonSerializable(typeof(AuditEntry))]
[JsonSerializable(typeof(VaultApplication.LoginRequest))]
[JsonSerializable(typeof(VaultApplication.PasswordRequest))]
internal partial class ServerJsonContext : JsonSerializerContext;
