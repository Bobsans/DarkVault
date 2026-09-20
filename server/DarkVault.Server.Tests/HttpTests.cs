using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DarkVault.Client;
using DarkVault.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NUnit.Framework;

namespace DarkVault.Server.Tests;

public sealed class HttpTests {
    [Test]
    public async Task HttpsSdkAndAdminAuthenticationWorkEndToEnd() {
        var directory = Path.Combine(Path.GetTempPath(), "dv-http-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        var certRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var ring = new KeyRing(Path.Combine(directory, "keys.json"), true);
        using var store = new VaultStore(Path.Combine(directory, "vault.db"), ring);
        store.SetPassword("test-password-for-http-only");
        var admin = new VaultStore.Principal("test", true);
        JsonElement Run(string op, object p) => JsonSerializer.SerializeToElement(store.Run(admin, op, JsonSerializer.SerializeToElement(p), Guid.NewGuid().ToString()), Wire.Json);
        var bucket = Run("bucket.create", new { name = "qa" }).GetProperty("id").GetString();
        var token = Run("token.create", new { name = "sdk", scopes = VaultStore.Scopes, bucketIds = new[] { bucket }, allBuckets = false, creatableBucketNames = Array.Empty<string>(), expiresAt = (string?)null }).GetProperty("token").GetString()!;
        await using var app = VaultApplication.Build([], store, ring, directory);
        // Test-only certificate pin; production clients use the OS trust store.
        app.Urls.Add("https://127.0.0.1:0");
        app.Configuration["Kestrel:Certificates:Default:Path"] = Path.Combine(directory, "test.pfx");
        await File.WriteAllBytesAsync(Path.Combine(directory, "test.pfx"), cert.Export(X509ContentType.Pfx));
        await app.StartAsync(); var url = app.Urls.Single();
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, c, _, _) => c?.Thumbprint == cert.Thumbprint });
        try {
            foreach (var path in new[] { "/", "/index.html", "/app.js", "/style.css" }) {
                using var asset = await http.GetAsync(url + path);
                Assert.That(asset.StatusCode, Is.EqualTo(HttpStatusCode.OK), path);
                Assert.That(asset.Headers.CacheControl?.NoStore, Is.True, path);
                Assert.That(asset.Headers.Contains("Content-Security-Policy"), Is.True, path);
            }
            var html = await http.GetStringAsync(url + "/");
            Assert.That(html, Does.Contain("id=\"login-form\"").And.Contain("src=\"/app.js\""));
            Assert.That(html, Does.Not.Contain("@page"));
            foreach (var path in new[] { "/api/v1/missing", "/admin/api/v1/missing", "/missing.js", "/protocol.js" }) {
                using var missing = await http.GetAsync(url + path);
                Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.NotFound), path);
            }
            using var client = new DarkVaultClient(url, token, http);
            var secret = await client.AddSecretAsync("qa", "ConnectionStrings:Main", "秘密\nvalue");
            Assert.That((await client.ReadBucketAsync("qa"))["ConnectionStrings:Main"], Is.EqualTo("秘密\nvalue"));
            var configuration = new ConfigurationBuilder(); await configuration.AddFromDarkVaultBucketAsync(client, "qa");
            Assert.That(configuration.Build()["ConnectionStrings:Main"], Is.EqualTo("秘密\nvalue"));
            var updated = await client.UpdateSecretAsync("qa", secret.Key, "updated", secret.Revision);
            Assert.That((await client.ReadSecretAsync("qa", secret.Key)).Value, Is.EqualTo("updated"));
            Assert.ThrowsAsync<DarkVaultException>(async () => await client.DeleteSecretAsync("qa", secret.Key, secret.Revision));
            await client.AddSecretAsync("qa", "case", "a"); await client.AddSecretAsync("qa", "CASE", "b");
            var empty = new ConfigurationBuilder(); Assert.ThrowsAsync<InvalidOperationException>(async () => await empty.AddFromDarkVaultBucketAsync(client, "qa")); Assert.That(empty.Sources, Is.Empty);
            using var anonymous = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "test-password-for-http-only" }); Assert.That(anonymous.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            var session = await http.GetFromJsonAsync<JsonElement>(url + "/admin/api/v1/session");
            http.DefaultRequestHeaders.Add("X-CSRF-Token", session.GetProperty("csrfToken").GetString());
            using var login = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "test-password-for-http-only" }); Assert.That(login.IsSuccessStatusCode, Is.True);
            var loggedIn = await http.GetFromJsonAsync<JsonElement>(url + "/admin/api/v1/session"); Assert.That(loggedIn.GetProperty("authenticated").GetBoolean(), Is.True);
            using var noToken = await http.PostAsync(url + "/api/v1/execute", new StringContent("invalid", Encoding.UTF8, "application/jose")); Assert.That(noToken.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            using var logout = await http.PostAsJsonAsync(url + "/admin/logout", new { }); Assert.That(logout.IsSuccessStatusCode, Is.True);
            Run("token.revoke", new { id = (await client.GetTokenInfoAsync()).Id }); Assert.ThrowsAsync<DarkVaultException>(async () => await client.ReadBucketAsync("qa"));
        } finally { await app.StopAsync(); store.Dispose(); Directory.Delete(directory, true); }
    }
}
