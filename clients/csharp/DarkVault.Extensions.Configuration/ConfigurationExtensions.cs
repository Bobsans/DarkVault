using DarkVault.Client;

namespace Microsoft.Extensions.Configuration;

public static class DarkVaultConfigurationExtensions {
    public static async Task<IConfigurationBuilder> AddFromDarkVaultBucketAsync(this IConfigurationBuilder builder,
        string server, string token, string bucket, CancellationToken cancellationToken = default) {
        using var client = new DarkVaultClient(server, token);
        return await builder.AddFromDarkVaultBucketAsync(client, bucket, cancellationToken);
    }
    public static async Task<IConfigurationBuilder> AddFromDarkVaultBucketAsync(this IConfigurationBuilder builder,
        DarkVaultClient client, string bucket, CancellationToken cancellationToken = default) {
        var secrets = await client.ReadBucketAsync(bucket, cancellationToken);
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (secrets.Keys.Any(key => !keys.Add(key))) throw new InvalidOperationException("Bucket contains case-insensitive key collisions.");
        return builder.AddInMemoryCollection(secrets);
    }
}
