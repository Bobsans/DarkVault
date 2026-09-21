using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DarkVault.Client;

public sealed class DarkVaultClient : IDisposable {
    private readonly HttpClient http;
    private readonly bool ownsHttp;
    private readonly Uri endpoint;
    private readonly string token;
    private CryptoKey? key;
    private DateTimeOffset keyFetched;

    public DarkVaultClient(string server, string token, HttpClient? httpClient = null) {
        endpoint = new Uri(server.Contains("://", StringComparison.Ordinal) ? server : "https://" + server);
        if (endpoint.Scheme != "https" || endpoint.UserInfo != "" || endpoint.Query != "" || endpoint.Fragment != "" || endpoint.AbsolutePath != "/")
            throw new ArgumentException("Use an HTTPS origin without credentials, path or query.", nameof(server));
        if (!Wire.IsToken(token)) throw new ArgumentException("Invalid DarkVault token format.", nameof(token));
        this.token = token;
        ownsHttp = httpClient is null;
        http = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
    }
    public string? DefaultBucket { get; private init; }

    public static DarkVaultClient FromUrl(string connectionString, HttpClient? httpClient = null) {
        var match = System.Text.RegularExpressions.Regex.Match(connectionString ?? "",
            @"\Ahttps://(dv1_[A-Za-z0-9_-]{60})@([^/?#@\s\\]+)/([a-z0-9][a-z0-9_-]{0,62})\z");
        if (!match.Success || !Uri.TryCreate("https://" + match.Groups[2].Value, UriKind.Absolute, out var origin) ||
            origin.Host.Length == 0 || origin.Port < 1 || origin.Port > 65535)
            throw new ArgumentException("Invalid DarkVault connection string.", nameof(connectionString));
        return new DarkVaultClient(origin.AbsoluteUri, match.Groups[1].Value, httpClient) { DefaultBucket = match.Groups[3].Value };
    }

    public static async Task<T> LoadConfigurationAsync<T>(string url,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken = default, HttpClient? httpClient = null) {
        using var client = FromUrl(url, httpClient);
        return await client.ReadConfigurationAsync(typeInfo, cancellationToken);
    }

    private string ResolveBucket(string? bucket) => bucket ?? DefaultBucket ??
        throw new InvalidOperationException("Specify a bucket or use a connection string containing one.");

    public void Dispose() { if (ownsHttp) http.Dispose(); }

    public Task<Bucket> AddBucketAsync(string name, string description = "", CancellationToken cancellationToken = default) =>
        ExecuteAsync<Bucket>("bucket.create", new { name, description }, cancellationToken);
    public Task<Bucket> GetBucketAsync(string bucket, CancellationToken cancellationToken = default) => ExecuteAsync<Bucket>("bucket.get", new { bucket }, cancellationToken);
    public Task<Page<Bucket>> ListBucketsAsync(string? cursor = null, int limit = 100, CancellationToken cancellationToken = default) =>
        ExecuteAsync<Page<Bucket>>("bucket.list", new { cursor, limit }, cancellationToken);
    public Task<BucketSnapshot> ReadBucketSnapshotAsync(string? bucket = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<BucketSnapshot>("bucket.read", new { bucket = ResolveBucket(bucket) }, cancellationToken);
    public async Task<IReadOnlyDictionary<string, string?>> ReadBucketAsync(string? bucket = null, CancellationToken cancellationToken = default) =>
        (await ReadBucketSnapshotAsync(bucket, cancellationToken)).Secrets;
    public async Task<IReadOnlyDictionary<string, JsonElement>> ReadTypedBucketAsync(string? bucket = null, CancellationToken cancellationToken = default) =>
        SecretValues.Typed(await ReadBucketSnapshotAsync(bucket, cancellationToken));
    public async Task<T> ReadConfigurationAsync<T>(string bucket, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default) =>
        SecretValues.Configuration(await ReadTypedBucketAsync(bucket, cancellationToken)).Deserialize(typeInfo) ?? throw new FormatException("Invalid configuration.");
    public Task<T> ReadConfigurationAsync<T>(System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default) =>
        ReadConfigurationAsync(ResolveBucket(null), typeInfo, cancellationToken);
    public Task<Bucket> UpdateBucketAsync(string bucket, string description, long expectedRevision, CancellationToken cancellationToken = default) =>
        ExecuteAsync<Bucket>("bucket.update", new { bucket, description, expectedRevision }, cancellationToken);
    public Task<Bucket> RenameBucketAsync(string bucket, string name, long expectedRevision, CancellationToken cancellationToken = default) =>
        ExecuteAsync<Bucket>("bucket.update", new { bucket, name, expectedRevision }, cancellationToken);
    public async Task DeleteBucketAsync(string bucket, long expectedRevision, bool recursive = false, CancellationToken cancellationToken = default) =>
        _ = await ExecuteAsync<JsonElement>("bucket.delete", new { bucket, expectedRevision, recursive }, cancellationToken);
    public Task<SecretMetadata> AddSecretAsync(string bucket, string key, string value, CancellationToken cancellationToken = default) =>
        ExecuteAsync<SecretMetadata>("secret.create", new { bucket, key, value }, cancellationToken);
    public Task<SecretMetadata> AddSecretAsync(string bucket, string key, JsonElement value, CancellationToken cancellationToken = default) =>
        WriteTypedSecretAsync("secret.create", bucket, key, value, null, cancellationToken);
    public Task<Secret> ReadSecretAsync(string bucket, string key, CancellationToken cancellationToken = default) =>
        ExecuteAsync<Secret>("secret.read", new { bucket, key }, cancellationToken);
    public Task<Page<SecretMetadata>> ListSecretsAsync(string bucket, string? cursor = null, int limit = 100, CancellationToken cancellationToken = default) =>
        ExecuteAsync<Page<SecretMetadata>>("secret.list", new { bucket, cursor, limit }, cancellationToken);
    public Task<SecretMetadata> UpdateSecretAsync(string bucket, string key, string value, long expectedRevision, CancellationToken cancellationToken = default) =>
        ExecuteAsync<SecretMetadata>("secret.update", new { bucket, key, value, expectedRevision }, cancellationToken);
    public Task<SecretMetadata> UpdateSecretAsync(string bucket, string key, JsonElement value, long expectedRevision, CancellationToken cancellationToken = default) =>
        WriteTypedSecretAsync("secret.update", bucket, key, value, expectedRevision, cancellationToken);
    public Task<SecretMetadata> SetSecretAsync(string bucket, string key, string value, long expectedRevision = 0, CancellationToken cancellationToken = default) =>
        ExecuteAsync<SecretMetadata>("secret.set", new { bucket, key, value, expectedRevision }, cancellationToken);
    public Task<SecretMetadata> SetSecretAsync(string bucket, string key, JsonElement value, long expectedRevision = 0, CancellationToken cancellationToken = default) =>
        WriteTypedSecretAsync("secret.set", bucket, key, value, expectedRevision, cancellationToken);
    private Task<SecretMetadata> WriteTypedSecretAsync(string operation, string bucket, string key, JsonElement input, long? revision, CancellationToken ct) {
        var (value, type) = SecretValues.Encode(input);
        var parameters = new Dictionary<string, object?> { ["bucket"] = bucket, ["key"] = key, ["value"] = value, ["type"] = type };
        if (revision is not null) parameters["expectedRevision"] = revision.Value;
        return ExecuteAsync<SecretMetadata>(operation, parameters, ct);
    }
    public async Task DeleteSecretAsync(string bucket, string key, long expectedRevision, CancellationToken cancellationToken = default) =>
        _ = await ExecuteAsync<JsonElement>("secret.delete", new { bucket, key, expectedRevision }, cancellationToken);
    public Task<TokenInfo> GetTokenInfoAsync(CancellationToken cancellationToken = default) => ExecuteAsync<TokenInfo>("token.info", new { }, cancellationToken);

    public async Task<T> ExecuteAsync<T>(string operation, object parameters, CancellationToken cancellationToken = default) {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        var read = operation.EndsWith(".read", StringComparison.Ordinal) || operation.EndsWith(".get", StringComparison.Ordinal) ||
                   operation.EndsWith(".list", StringComparison.Ordinal) || operation == "token.info";
        var keyRetry = false;
        for (var attempt = 0; ; attempt++) {
            try {
                var current = key;
                if (current is null || DateTimeOffset.UtcNow - keyFetched > TimeSpan.FromMinutes(5) || current.NotAfter <= DateTimeOffset.UtcNow) {
                    using var discovery = new HttpRequestMessage(HttpMethod.Get, new Uri(endpoint, "api/v1/crypto/key"));
                    using var response = await http.SendAsync(discovery, HttpCompletionOption.ResponseHeadersRead, ct);
                    EnsureOrigin(response);
                    if (!response.IsSuccessStatusCode) throw new DarkVaultException("key_unavailable", (int)response.StatusCode);
                    current = Wire.Parse<CryptoKey>(await Wire.ReadBodyAsync(await response.Content.ReadAsStreamAsync(ct), ct));
                    if (current.ProtocolVersion != 1 || current.NotAfter <= DateTimeOffset.UtcNow || !Guid.TryParse(current.ServerId, out _))
                        throw new DarkVaultException("invalid_key", 0);
                    using var validated = Wire.Import(current.PublicKey);
                    key = current; keyFetched = DateTimeOffset.UtcNow;
                }
                using var reply = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var id = Guid.NewGuid().ToString();
                var request = new VaultRequest(1, id, DateTimeOffset.UtcNow, current.ServerId, "data", operation,
                    Wire.ToElement(parameters), Wire.Export(reply));
                var body = Wire.Encrypt(Wire.Serialize(request), current.PublicKey, current.Kid, "darkvault-request+jwe");
                using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(endpoint, "api/v1/execute"));
                message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/jose"));
                message.Content = new StringContent(body, Encoding.UTF8, "application/jose");
                using var result = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                EnsureOrigin(result);
                var text = await Wire.ReadBodyAsync(await result.Content.ReadAsStreamAsync(ct), ct);
                if (result.Content.Headers.ContentType?.MediaType != "application/jose") {
                    string code = "transport_error";
                    try { using var error = JsonDocument.Parse(text); code = error.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code; } catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { }
                    if (code == "unknown_key" && result.StatusCode == HttpStatusCode.BadRequest && !keyRetry) { key = null; keyRetry = true; continue; }
                    if (result.IsSuccessStatusCode) throw new DarkVaultException("unencrypted_response", (int)result.StatusCode, id);
                    if (read && attempt < 2 && (result.StatusCode == HttpStatusCode.TooManyRequests || (int)result.StatusCode >= 500)) {
                        var delay = result.Headers.RetryAfter?.Delta ?? TimeSpan.FromMilliseconds(200 * (attempt + 1) + Random.Shared.Next(100));
                        await Task.Delay(delay, ct); continue;
                    }
                    throw new DarkVaultException(code, (int)result.StatusCode, id);
                }
                var plain = Wire.Decrypt(text, reply, id, "darkvault-response+jwe");
                var envelope = JsonSerializer.Deserialize(plain, Wire.TypeInfo<VaultResponse>(Wire.ResponseJson)) ?? throw new FormatException();
                if (envelope.V != 1 || envelope.RequestId != id || envelope.ServerId != current.ServerId || envelope.Audience != "data" ||
                    envelope.Operation != operation || envelope.Status != (int)result.StatusCode) throw new DarkVaultException("invalid_response", 0, id);
                if (envelope.Error is not null) throw new DarkVaultException(envelope.Error.Code, envelope.Status, id);
                if (!result.IsSuccessStatusCode || envelope.Data is null) throw new DarkVaultException("invalid_response", 0, id);
                return envelope.Data.Value.Deserialize(Wire.TypeInfo<T>(Wire.ResponseJson)) ?? throw new DarkVaultException("invalid_response", 0, id);
            } catch (HttpRequestException) when (read && attempt < 2) {
                await Task.Delay(200 * (attempt + 1) + Random.Shared.Next(100), ct);
            } catch (HttpRequestException) {
                throw new DarkVaultException(read ? "unavailable" : "outcome_unknown", 0);
            } catch (Exception ex) when (ex is FormatException or InvalidDataException or JsonException or CryptographicException or Jose.JoseException) {
                throw new DarkVaultException("invalid_response", 0);
            }
        }
    }
    private void EnsureOrigin(HttpResponseMessage response) {
        if (response.RequestMessage?.RequestUri?.GetLeftPart(UriPartial.Authority) != endpoint.GetLeftPart(UriPartial.Authority))
            throw new DarkVaultException("redirect_rejected", (int)response.StatusCode);
    }
}
