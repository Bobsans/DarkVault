using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DarkVault.Client;
using DarkVault.Server;

// This executable is test infrastructure only. It is never included in server packages.
var root = Path.GetFullPath(args[0]);
var state = Path.Combine(root, ".local", "acceptance-" + Guid.NewGuid().ToString("N"));
ServerCommands.SecureDirectory(state);
using var rsa = RSA.Create(2048);
var certificateRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(System.Net.IPAddress.Loopback);
certificateRequest.CertificateExtensions.Add(san.Build());
using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
var pfx = Path.Combine(state, "server.pfx"); await File.WriteAllBytesAsync(pfx, certificate.Export(X509ContentType.Pfx));
var ca = Path.Combine(state, "ca.crt"); await File.WriteAllTextAsync(ca, certificate.ExportCertificatePem());
var ring = new KeyRing(Path.Combine(state, "keyring.json"), true);
using var store = new VaultStore(Path.Combine(state, "vault.db"), ring); store.SetPassword("acceptance-test-password-only");
var admin = new VaultStore.Principal("acceptance", true);
object Run(string op, object p) => store.Run(admin, op, JsonSerializer.SerializeToElement(p), Guid.NewGuid().ToString());
Run("bucket.create", new { name = "interop" });
var issued = JsonSerializer.SerializeToElement(Run("token.create", new { name = "acceptance", scopes = VaultStore.Scopes, bucketIds = Array.Empty<string>(), allBuckets = true, creatableBucketNames = Array.Empty<string>(), expiresAt = (string?)null }), Wire.Json);
var tokenFile = Path.Combine(state, "test.token"); KeyRing.SavePrivate(tokenFile, issued.GetProperty("token").GetString()!);
var fixturePath = Path.Combine(root, "tests", "fixtures", "jwe.json");
if (!File.Exists(fixturePath)) {
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var p = key.ExportParameters(true);
    var publicKey = Wire.Export(key);
    const string plaintext = "{\"value\":\"Unicode: 秘密\\nline\",\"empty\":\"\"}";
    var compact = Wire.Encrypt(plaintext, publicKey, "interop-test", "darkvault-response+jwe");
    Directory.CreateDirectory(Path.GetDirectoryName(fixturePath)!);
    await File.WriteAllTextAsync(fixturePath, Wire.Serialize(new { notice = "PUBLIC TEST KEY. Never use in production.",
        jwk = new { kty = "EC", crv = "P-256", x = publicKey.X, y = publicKey.Y, d = Wire.Base64(p.D!) },
        kid = "interop-test", type = "darkvault-response+jwe", plaintext, compact,
        token = "dv1_" + Wire.Base64(Enumerable.Range(0,45).Select(i => (byte)i).ToArray()),
        tokenHash = Wire.HashToken("dv1_" + Wire.Base64(Enumerable.Range(0,45).Select(i => (byte)i).ToArray())) }));
}
var app = VaultApplication.Build([], store, ring, state);
app.Urls.Add("https://127.0.0.1:18866"); app.Configuration["Kestrel:Certificates:Default:Path"] = pfx;
await File.WriteAllTextAsync(Path.Combine(root, ".local", "acceptance.json"), Wire.Serialize(new { url = "https://127.0.0.1:18866", ca, tokenFile }));
await app.RunAsync();
