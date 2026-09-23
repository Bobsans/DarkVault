using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DarkVault.Client;
using DarkVault.Server;

// This executable is test infrastructure only. It is never included in server packages.
var root = Path.GetFullPath(args[0]);
if (args.Skip(1).SequenceEqual(["--check"])) {
    using var descriptor = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, ".local", "acceptance.json")));
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
    var name = "csharp_" + Guid.NewGuid().ToString("N");
    await client.AddBucketAsync(name);
    var secret = await client.AddSecretAsync(name, "key", "native-秘密");
    if ((await client.ReadSecretAsync(name, "key")).Value != "native-秘密") throw new InvalidOperationException("C# read mismatch.");
    var updated = await client.UpdateSecretAsync(name, "key", "updated", secret.Revision);
    if ((await client.ReadBucketAsync(name))["key"] != "updated") throw new InvalidOperationException("C# snapshot mismatch.");
    if ((await client.ListSecretsAsync(name)).Items.Count != 1) throw new InvalidOperationException("C# list mismatch.");
    await client.DeleteSecretAsync(name, "key", updated.Revision);
    await client.DeleteBucketAsync(name, (await client.GetBucketAsync(name)).Revision);
    Console.WriteLine("C# SDK verified against the published server.");
    return;
}
var state = Path.Combine(root, ".local", "acceptance-" + Guid.NewGuid().ToString("N"));
ServerCommands.SecureDirectory(state);
// A test CA issues the server certificate so clients verify a real chain and hostname, not a pinned leaf.
var from = DateTimeOffset.UtcNow.AddMinutes(-1); var until = DateTimeOffset.UtcNow.AddDays(1);
using var authorityKey = RSA.Create(2048);
var authorityRequest = new CertificateRequest("CN=DarkVault acceptance CA", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
authorityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
authorityRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(authorityRequest.PublicKey, false));
using var authority = authorityRequest.CreateSelfSigned(from, until);
using var rsa = RSA.Create(2048);
var certificateRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(System.Net.IPAddress.Loopback);
certificateRequest.CertificateExtensions.Add(san.Build());
certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")], false));
certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
using var leaf = certificateRequest.Create(authority, from, until, RandomNumberGenerator.GetBytes(16));
using var certificate = leaf.CopyWithPrivateKey(rsa);
var pfx = Path.Combine(state, "server.pfx"); await File.WriteAllBytesAsync(pfx, certificate.Export(X509ContentType.Pfx));
var ca = Path.Combine(state, "ca.crt"); await File.WriteAllTextAsync(ca, authority.ExportCertificatePem());
var ring = new KeyRing(Path.Combine(state, "keyring.json"), true);
using var store = new VaultStore(Path.Combine(state, "vault.db"), ring); store.SetPassword("acceptance-test-password-only");
var admin = new VaultStore.Principal("acceptance", true);
object Run(string op, object p) => store.Run(admin, op, JsonSerializer.SerializeToElement(p), Guid.NewGuid().ToString());
Run("bucket.create", new { name = "interop" });
var issued = JsonSerializer.SerializeToElement(Run("token.create", new { name = "acceptance", scopes = VaultStore.Scopes, bucketIds = Array.Empty<string>(), allBuckets = true, creatableBucketNames = Array.Empty<string>(), expiresAt = (string?)null }), JsonSerializerOptions.Web);
var tokenFile = Path.Combine(state, "test.token"); KeyRing.SavePrivate(tokenFile, issued.GetProperty("token").GetString()!);
var fixturePath = Path.Combine(root, "tests", "fixtures", "jwe.json");
if (!File.Exists(fixturePath)) throw new FileNotFoundException("The shared public JWE fixture is required.", fixturePath);
await File.WriteAllTextAsync(Path.Combine(root, ".local", "acceptance.json"), JsonSerializer.Serialize(new { url = "https://127.0.0.1:18866", ca, tokenFile }, JsonSerializerOptions.Web));
// Seed the same temporary state for testing the published native server instead of this host.
if (args.Skip(1).SequenceEqual(["--prepare"])) return;
var app = VaultApplication.Build([], store, ring, state);
app.Urls.Add("https://127.0.0.1:18866"); app.Configuration["Kestrel:Certificates:Default:Path"] = pfx;
await app.RunAsync();
