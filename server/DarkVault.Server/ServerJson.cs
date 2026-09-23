using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

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

internal sealed record HealthResult(string Status);
internal sealed record SessionResult(bool Authenticated, string? CsrfToken, string? ServerVersion);
internal sealed record StoredSecretMetadata(string Id, string BucketId, string Key, long Revision, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt, string Type) {
    public SecretMetadata ToContract() => new(Id, BucketId, Key, Revision, CreatedAt, UpdatedAt, Type);
    public static StoredSecretMetadata FromContract(SecretMetadata value) => new(value.Id, value.BucketId, value.Key, value.Revision, value.CreatedAt, value.UpdatedAt, value.Type);
}
internal sealed record StoredBucket(string Id, string Name, string Description, long Revision, DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt) {
    public Bucket ToContract() => new(Id, Name, Description, Revision, CreatedAt, UpdatedAt);
    public static StoredBucket FromContract(Bucket value) => new(value.Id, value.Name, value.Description, value.Revision, value.CreatedAt, value.UpdatedAt);
}
// Storage and audit shape of a token; kept separate from the wire TokenInfo so SDK changes cannot alter the database format.
public sealed record StoredTokenInfo(string Id, string Name, string[] Scopes, string[] BucketIds, bool AllBuckets, string[] CreatableBucketNames, DateTimeOffset? ExpiresAt) {
    public TokenInfo ToContract() => new(Id, Name, Scopes, BucketIds, AllBuckets, CreatableBucketNames, ExpiresAt);
    public static StoredTokenInfo FromContract(TokenInfo value) => new(value.Id, value.Name, value.Scopes, value.BucketIds, value.AllBuckets, value.CreatableBucketNames, value.ExpiresAt);
}
internal sealed record AuthenticationResult(bool Authenticated);
internal sealed record PasswordResult(bool Changed);
internal sealed record ErrorResult(VaultError Error);
internal sealed record DeleteResult(bool Deleted);
internal sealed record RevokeResult(bool Revoked);
internal sealed record TokenCreated(VaultStore.TokenRecord Metadata, string Token);
internal sealed record AuditEntry(DateTimeOffset Time, string Principal, string Operation, string? BucketId, string? SecretId, string RequestId, string Result,
    string Kind = "operation", string? PrincipalType = null, string? PrincipalName = null, string? TraceId = null,
    DateTimeOffset? StartedAt = null, string? SourceIp = null, string? PeerIp = null, string? Method = null,
    string? Path = null, int? StatusCode = null, double? DurationMs = null, AuditDetails? Details = null);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(KeyRing.Ring))]
[JsonSerializable(typeof(KeyRing.ProtectedRing))]
[JsonSerializable(typeof(VaultStore.Admin))]
[JsonSerializable(typeof(VaultStore.MfaState))]
[JsonSerializable(typeof(AdminMfa.OptionsResult))]
[JsonSerializable(typeof(AdminMfa.VerifyRequest))]
[JsonSerializable(typeof(AdminMfa.VerifyResult))]
[JsonSerializable(typeof(VaultStore.TokenRecord))]
[JsonSerializable(typeof(VaultStore.StoredSecret))]
[JsonSerializable(typeof(StoredBucket))]
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
