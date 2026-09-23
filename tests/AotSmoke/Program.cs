using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using DarkVault.Client;
using Microsoft.Extensions.Configuration;

// Test infrastructure only: publishes the C# SDK with Native AOT and runs it against the acceptance host.
using var descriptor = JsonDocument.Parse(await File.ReadAllTextAsync(args[0]));
var info = descriptor.RootElement;
using var pinned = X509CertificateLoader.LoadCertificateFromFile(info.GetProperty("ca").GetString()!);
using var http = new HttpClient(new HttpClientHandler {
    AllowAutoRedirect = false,
    // The test CA replaces the OS trust store; hostname and chain are still verified.
    ServerCertificateCustomValidationCallback = (_, cert, chain, errors) => {
        if (cert is null || chain is null || (errors & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.Add(pinned);
        return chain.Build(cert);
    }
});
using var client = new DarkVaultClient(info.GetProperty("url").GetString()!, (await File.ReadAllTextAsync(info.GetProperty("tokenFile").GetString()!)).Trim(), http);
var name = "aot_" + Guid.NewGuid().ToString("N");
await client.AddBucketAsync(name);
var text = await client.AddSecretAsync(name, "Service:Name", "native-秘密");
using var port = JsonDocument.Parse("6379");
await client.AddSecretAsync(name, "Service:Port", port.RootElement);
if ((await client.ReadSecretAsync(name, "Service:Name")).Value != "native-秘密") throw new InvalidOperationException("AOT read mismatch.");
var settings = await client.ReadConfigurationAsync(name, SmokeJson.Default.Settings);
if (settings.Service.Name != "native-秘密" || settings.Service.Port != 6379) throw new InvalidOperationException("AOT typed configuration mismatch.");
var configuration = (await new ConfigurationBuilder().AddFromDarkVaultAsync(client, name)).Build();
if (configuration["Service:Port"] != "6379") throw new InvalidOperationException("AOT configuration provider mismatch.");
await client.UpdateSecretAsync(name, "Service:Name", "updated", text.Revision);
if ((await client.ListSecretsAsync(name)).Items.Count != 2) throw new InvalidOperationException("AOT list mismatch.");
if ((await client.GetTokenInfoAsync()).Scopes.Length == 0) throw new InvalidOperationException("AOT token info mismatch.");
await client.DeleteBucketAsync(name, (await client.GetBucketAsync(name)).Revision, recursive: true);
Console.WriteLine("C# SDK verified under Native AOT.");

internal sealed record Settings(ServiceSettings Service);
internal sealed record ServiceSettings(string Name, int Port);

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(Settings))]
internal sealed partial class SmokeJson : JsonSerializerContext;
