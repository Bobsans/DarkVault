using DarkVault.Client;

namespace Microsoft.Extensions.Configuration;

public static class DarkVaultConfigurationExtensions {
    public static IConfigurationBuilder AddFromDarkVault(this IConfigurationBuilder builder,
        CancellationToken cancellationToken = default, HttpClient? httpClient = null) =>
        builder.AddFromDarkVault(EnvironmentUrl(), cancellationToken, httpClient);

    public static Task<IConfigurationBuilder> AddFromDarkVaultAsync(this IConfigurationBuilder builder,
        CancellationToken cancellationToken = default, HttpClient? httpClient = null) =>
        builder.AddFromDarkVaultAsync(EnvironmentUrl(), cancellationToken, httpClient);

    private static string EnvironmentUrl() {
        var url = Environment.GetEnvironmentVariable("DARKVAULT_URL");
        if (string.IsNullOrWhiteSpace(url))
            throw new InvalidOperationException("Set DARKVAULT_URL in the process environment before loading DarkVault configuration.");
        return url;
    }

    // Startup-only synchronous bridge; the worker avoids capturing the caller's synchronization context.
    public static IConfigurationBuilder AddFromDarkVault(this IConfigurationBuilder builder,
        string url, CancellationToken cancellationToken = default, HttpClient? httpClient = null) =>
        Task.Run(() => builder.AddFromDarkVaultAsync(url, cancellationToken, httpClient), cancellationToken).GetAwaiter().GetResult();

    public static async Task<IConfigurationBuilder> AddFromDarkVaultAsync(this IConfigurationBuilder builder,
        string url, CancellationToken cancellationToken = default, HttpClient? httpClient = null) {
        using var client = DarkVaultClient.FromUrl(url, httpClient);
        return await builder.AddFromDarkVaultAsync(client, client.DefaultBucket!, cancellationToken);
    }

    public static async Task<IConfigurationBuilder> AddFromDarkVaultAsync(this IConfigurationBuilder builder,
        string server, string token, string bucket, CancellationToken cancellationToken = default) {
        using var client = new DarkVaultClient(server, token);
        return await builder.AddFromDarkVaultAsync(client, bucket, cancellationToken);
    }
    public static async Task<IConfigurationBuilder> AddFromDarkVaultAsync(this IConfigurationBuilder builder,
        DarkVaultClient client, string bucket, CancellationToken cancellationToken = default) {
        var snapshot = await client.ReadBucketSnapshotAsync(bucket, cancellationToken);
        var secrets = SecretValues.Typed(snapshot).ToDictionary(p => p.Key,
            p => p.Value.ValueKind == System.Text.Json.JsonValueKind.Null ? null : snapshot.Secrets[p.Key]);
        try { SecretValues.ValidateConfigurationPaths(secrets.Keys); } catch (ArgumentException ex) { throw new InvalidOperationException("Bucket contains conflicting configuration paths.", ex); }
        return builder.AddInMemoryCollection(secrets);
    }
}
