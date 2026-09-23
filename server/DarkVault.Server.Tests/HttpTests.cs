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
    private static readonly JsonSerializerOptions TestJson = new(JsonSerializerDefaults.Web);
    [Test, NonParallelizable]
    public async Task HttpsSdkAndAdminAuthenticationWorkEndToEnd() {
        var directory = Path.Combine(Path.GetTempPath(), "dv-http-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        var certRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var ring = new KeyRing(Path.Combine(directory, "keys.json"), true);
        using var store = new VaultStore(Path.Combine(directory, "vault.db"), ring);
        store.SetPassword("test-password-for-http-only");
        var admin = new VaultStore.Principal("test", true);
        JsonElement Run(string op, object p) => JsonSerializer.SerializeToElement(store.Run(admin, op, JsonSerializer.SerializeToElement(p), Guid.NewGuid().ToString()), TestJson);
        var bucket = Run("bucket.create", new { name = "qa" }).GetProperty("id").GetString();
        var token = Run("token.create", new { name = "sdk", scopes = VaultStore.Scopes, bucketIds = new[] { bucket }, allBuckets = false, creatableBucketNames = Array.Empty<string>(), expiresAt = (string?)null }).GetProperty("token").GetString()!;
        await using var app = VaultApplication.Build(["--DARKVAULT_TRUSTED_PROXIES=127.0.0.1,::1"], store, ring, directory);
        // Test-only certificate pin; production clients use the OS trust store.
        app.Urls.Add("https://127.0.0.1:0");
        app.Configuration["Kestrel:Certificates:Default:Path"] = Path.Combine(directory, "test.pfx");
        await File.WriteAllBytesAsync(Path.Combine(directory, "test.pfx"), cert.Export(X509ContentType.Pfx));
        await app.StartAsync(); var url = app.Urls.Single();
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, c, _, _) => c?.Thumbprint == cert.Thumbprint });
        http.DefaultRequestHeaders.Add("X-Forwarded-For", "198.51.100.42");
        http.DefaultRequestHeaders.Add("Origin", url);
        using var passkey = new TestPasskey();
        try {
            foreach (var path in new[] { "/", "/index.html", "/app.js", "/style.css", "/admin", "/admin/buckets", "/admin/buckets/qa", "/admin/tokens", "/admin/logs?kind=http", "/admin/settings" }) {
                using var asset = await http.GetAsync(url + path);
                Assert.That(asset.StatusCode, Is.EqualTo(HttpStatusCode.OK), path);
                Assert.That(asset.Headers.CacheControl?.NoStore, Is.True, path);
                Assert.That(asset.Headers.Contains("Content-Security-Policy"), Is.True, path);
            }
            using (var proxied = await http.GetAsync(url + "/metrics"))
                Assert.That(proxied.StatusCode, Is.EqualTo(HttpStatusCode.NotFound), "metrics through a proxy");
            using (var local = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, c, _, _) => c?.Thumbprint == cert.Thumbprint })) {
                using var metrics = await local.GetAsync(url + "/metrics");
                Assert.That(metrics.StatusCode, Is.EqualTo(HttpStatusCode.OK));
                Assert.That(await metrics.Content.ReadAsStringAsync(), Does.Contain("darkvault_"));
            }
            var html = await http.GetStringAsync(url + "/");
            Assert.That(html, Does.Contain("id=\"login-form\"").And.Contain("src=\"/app.js\""));
            Assert.That(html, Does.Not.Contain("@page"));
            foreach (var path in new[] { "/api/v1/missing", "/admin/api/v1/missing", "/missing.js", "/protocol.js", "/admin/missing", "/admin/missing.js", "/admin/buckets/invalid.html" }) {
                using var missing = await http.GetAsync(url + path);
                Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.NotFound), path);
            }
            using var client = new DarkVaultClient(url, token, http);
            var secret = await client.AddSecretAsync("qa", "ConnectionStrings:Main", "秘密\nvalue");
            Assert.That((await client.ReadBucketAsync("qa"))["ConnectionStrings:Main"], Is.EqualTo("秘密\nvalue"));
            var renamed = await client.RenameBucketAsync("qa", "qa-renamed", secret.Revision);
            Assert.That(renamed.Id, Is.EqualTo(bucket));
            Assert.That((await client.ReadSecretAsync("qa-renamed", "ConnectionStrings:Main")).Value, Is.EqualTo("秘密\nvalue"));
            await client.RenameBucketAsync("qa-renamed", "qa", renamed.Revision);
            var connectionUrl = url.Replace("https://", "https://" + token + "@") + "/qa";
            using var connectionClient = DarkVaultClient.FromUrl(connectionUrl, http);
            Assert.That((await connectionClient.ReadBucketAsync())["ConnectionStrings:Main"], Is.EqualTo("秘密\nvalue"));
            var configuration = new ConfigurationBuilder(); await configuration.AddFromDarkVaultAsync(client, "qa");
            Assert.That(configuration.Build()["ConnectionStrings:Main"], Is.EqualTo("秘密\nvalue"));
            await client.AddSecretAsync("qa", "Redis:Port", SecretValues.Parse("6379", "number"));
            await client.AddSecretAsync("qa", "Redis:Enabled", SecretValues.Parse("false", "boolean"));
            await client.AddSecretAsync("qa", "Redis:Optional", SecretValues.Parse("null", "null"));
            var typedConfig = await client.ReadConfigurationAsync("qa", Wire.TypeInfo<JsonElement>());
            Assert.That(typedConfig.GetProperty("Redis").GetProperty("Port").GetInt32(), Is.EqualTo(6379));
            Assert.That(typedConfig.GetProperty("Redis").GetProperty("Enabled").GetBoolean(), Is.False);
            var stringConfig = new ConfigurationBuilder(); await stringConfig.AddFromDarkVaultAsync(client, "qa");
            Assert.That(stringConfig.Build()["Redis:Port"], Is.EqualTo("6379"));
            Assert.That(stringConfig.Build()["Redis:Optional"], Is.Null);
            var loaded = await DarkVaultClient.LoadConfigurationAsync(connectionUrl, Wire.TypeInfo<JsonElement>(), httpClient: http);
            Assert.That(loaded.GetProperty("Redis").GetProperty("Port").GetInt32(), Is.EqualTo(6379));
            var syncConfiguration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Redis:Port"] = "1" });
            Assert.That(syncConfiguration.AddFromDarkVault(connectionUrl, httpClient: http), Is.SameAs(syncConfiguration));
            Assert.That(syncConfiguration.Build()["Redis:Port"], Is.EqualTo("6379"));
            Assert.That(syncConfiguration.Build()["Redis:Optional"], Is.Null);
            var asyncConfiguration = new ConfigurationBuilder();
            Assert.That(await asyncConfiguration.AddFromDarkVaultAsync(connectionUrl, httpClient: http), Is.SameAs(asyncConfiguration));
            Assert.That(asyncConfiguration.Build()["Redis:Enabled"], Is.EqualTo("false"));
            var previousUrl = Environment.GetEnvironmentVariable("DARKVAULT_URL");
            try {
                foreach (var missing in new string?[] { null, "", " \t " }) {
                    Environment.SetEnvironmentVariable("DARKVAULT_URL", missing);
                    var missingConfiguration = new ConfigurationBuilder();
                    Assert.That(Assert.Throws<InvalidOperationException>(() => missingConfiguration.AddFromDarkVault())!.Message,
                        Does.Contain("DARKVAULT_URL"));
                    Assert.ThrowsAsync<InvalidOperationException>(async () => await missingConfiguration.AddFromDarkVaultAsync());
                    Assert.That(missingConfiguration.Sources, Is.Empty);
                    Assert.ThrowsAsync<InvalidOperationException>(async () => await DarkVaultClient.LoadConfigurationAsync(Wire.TypeInfo<JsonElement>()));
                }
                Environment.SetEnvironmentVariable("DARKVAULT_URL", connectionUrl);
                var environmentSettings = await DarkVaultClient.LoadConfigurationAsync(Wire.TypeInfo<JsonElement>(), httpClient: http);
                Assert.That(environmentSettings.GetProperty("Redis").GetProperty("Port").GetInt32(), Is.EqualTo(6379));
                var environmentConfiguration = new ConfigurationBuilder();
                environmentConfiguration.AddFromDarkVault(httpClient: http);
                Assert.That(environmentConfiguration.Build()["Redis:Port"], Is.EqualTo("6379"));
                var asyncEnvironmentConfiguration = new ConfigurationBuilder();
                await asyncEnvironmentConfiguration.AddFromDarkVaultAsync(httpClient: http);
                Assert.That(asyncEnvironmentConfiguration.Build()["Redis:Enabled"], Is.EqualTo("false"));
                using var environmentCancelled = new CancellationTokenSource(); environmentCancelled.Cancel();
                Assert.CatchAsync<OperationCanceledException>(async () =>
                    await new ConfigurationBuilder().AddFromDarkVaultAsync(environmentCancelled.Token, http));
                Assert.CatchAsync<OperationCanceledException>(async () =>
                    await DarkVaultClient.LoadConfigurationAsync(Wire.TypeInfo<JsonElement>(), environmentCancelled.Token, http));
                Environment.SetEnvironmentVariable("DARKVAULT_URL", "invalid");
                await DarkVaultClient.LoadConfigurationAsync(connectionUrl, Wire.TypeInfo<JsonElement>(), httpClient: http);
                await new ConfigurationBuilder().AddFromDarkVaultAsync(connectionUrl, httpClient: http);
            } finally {
                Environment.SetEnvironmentVariable("DARKVAULT_URL", previousUrl);
            }
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            Assert.CatchAsync<OperationCanceledException>(async () => await new ConfigurationBuilder().AddFromDarkVaultAsync(connectionUrl, cancelled.Token, http));
            var updated = await client.UpdateSecretAsync("qa", secret.Key, "updated", secret.Revision);
            Assert.That((await client.ReadSecretAsync("qa", secret.Key)).Value, Is.EqualTo("updated"));
            Assert.ThrowsAsync<DarkVaultException>(async () => await client.DeleteSecretAsync("qa", secret.Key, secret.Revision));
            await client.AddSecretAsync("qa", "case", "a"); await client.AddSecretAsync("qa", "CASE", "b");
            var empty = new ConfigurationBuilder(); Assert.ThrowsAsync<InvalidOperationException>(async () => await empty.AddFromDarkVaultAsync(client, "qa")); Assert.That(empty.Sources, Is.Empty);
            var rejectedConfiguration = new ConfigurationBuilder();
            Assert.Throws<InvalidOperationException>(() => rejectedConfiguration.AddFromDarkVault(connectionUrl, httpClient: http));
            Assert.That(rejectedConfiguration.Sources, Is.Empty);
            using var anonymous = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "test-password-for-http-only" }); Assert.That(anonymous.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            var session = await http.GetFromJsonAsync<JsonElement>(url + "/admin/api/v1/session");
            Assert.That(session.GetProperty("authenticated").GetBoolean(), Is.False);
            Assert.That(session.GetProperty("serverVersion").ValueKind, Is.EqualTo(JsonValueKind.Null));
            http.DefaultRequestHeaders.Add("X-CSRF-Token", session.GetProperty("csrfToken").GetString());
            using var login = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "test-password-for-http-only" }); Assert.That(login.IsSuccessStatusCode, Is.True);
            var pendingSession = await http.GetFromJsonAsync<JsonElement>(url + "/admin/api/v1/session"); Assert.That(pendingSession.GetProperty("authenticated").GetBoolean(), Is.False);
            await passkey.Finish(http, url, login);
            using var authenticatedSessionResponse = await http.GetAsync(url + "/admin/api/v1/session");
            var traceId = authenticatedSessionResponse.Headers.GetValues("X-Request-Id").Single();
            Assert.That(Guid.TryParse(traceId, out _), Is.True);
            var loggedIn = JsonSerializer.Deserialize<JsonElement>(await authenticatedSessionResponse.Content.ReadAsStringAsync());
            Assert.That(loggedIn.GetProperty("authenticated").GetBoolean(), Is.True);
            Assert.That(loggedIn.GetProperty("serverVersion").GetString(), Is.Not.Empty);
            var correlation = Run("audit.list", new { search = traceId, limit = 10 });
            Assert.That(correlation.GetProperty("items").EnumerateArray().Any(item => item.GetProperty("traceId").GetString() == traceId), Is.True);
            using var noToken = await http.PostAsync(url + "/api/v1/execute", new StringContent("invalid", Encoding.UTF8, "application/jose")); Assert.That(noToken.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            using (var malformed = new HttpRequestMessage(HttpMethod.Post, url + "/api/v1/execute")) {
                malformed.Headers.Authorization = new("Bearer", token);
                malformed.Content = new StringContent("private-malformed-body", Encoding.UTF8, "application/jose");
                using var rejected = await http.SendAsync(malformed); Assert.That(rejected.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            }
            using var query = await http.GetAsync(url + "/health/ready?token=private-query-value");
            using var logout = await http.PostAsJsonAsync(url + "/admin/logout", new { }); Assert.That(logout.IsSuccessStatusCode, Is.True);
            using var loginAgain = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "test-password-for-http-only" }); Assert.That(loginAgain.IsSuccessStatusCode, Is.True);
            await passkey.Finish(http, url, loginAgain);
            using var password = await http.PostAsJsonAsync(url + "/admin/password", new { currentPassword = "test-password-for-http-only", newPassword = "new-test-password-for-http-only" }); Assert.That(password.IsSuccessStatusCode, Is.True);
            Run("token.revoke", new { id = (await client.GetTokenInfoAsync()).Id }); Assert.ThrowsAsync<DarkVaultException>(async () => await client.ReadBucketAsync("qa"));
            for (var i = 0; i < 11; i++) {
                using var attempt = await http.PostAsJsonAsync(url + "/admin/login", new { username = "admin", password = "wrong-test-password" });
                if (i == 10) { Assert.That(attempt.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests)); Assert.That(attempt.Headers.RetryAfter, Is.Not.Null); }
            }
            // Stop waits for the last HTTP request's completion audit before inspecting SQLite.
            await app.StopAsync();
            var audit = Run("audit.list", new { limit = 200 }).GetProperty("items").EnumerateArray().ToArray();
            var requests = audit.Where(e => e.GetProperty("kind").GetString() == "http").ToArray();
            Assert.That(requests, Is.Not.Empty);
            Assert.That(requests.All(e => e.GetProperty("sourceIp").GetString() == "198.51.100.42"), Is.True);
            Assert.That(requests.All(e => e.GetProperty("peerIp").GetString() is "127.0.0.1" or "::ffff:127.0.0.1"), Is.True);
            Assert.That(requests.All(e => e.GetProperty("durationMs").GetDouble() >= 0 && Guid.TryParse(e.GetProperty("traceId").GetString(), out _)), Is.True);
            foreach (var path in new[] { "/api/v1/execute", "/admin/api/v1/session" })
                Assert.That(requests.Any(e => e.GetProperty("path").GetString() == path), Is.True, path);
            Assert.That(requests.Any(e => e.GetProperty("path").GetString() == "/health/ready"), Is.False);
            Assert.That(requests.Any(e => e.GetProperty("principal").GetString() == "anonymous" || e.GetProperty("statusCode").GetInt32() == 429), Is.False);
            foreach (var result in new[] { "invalid_envelope", "revision_conflict" })
                Assert.That(requests.Any(e => e.GetProperty("result").GetString() == result), Is.True, result);
            foreach (var operation in new[] { "admin.logout", "admin.password" })
                Assert.That(requests.Any(e => e.GetProperty("operation").GetString() == operation && e.GetProperty("principal").GetString() == store.Administrator!.Id && e.GetProperty("result").GetString() == "success"), Is.True, operation);
            var created = audit.Single(e => e.GetProperty("kind").GetString() == "operation" && e.GetProperty("secretId").GetString() == secret.Id && e.GetProperty("operation").GetString() == "secret.create");
            var completed = requests.Single(e => e.GetProperty("traceId").GetString() == created.GetProperty("traceId").GetString());
            Assert.That(completed.GetProperty("requestId").GetString(), Is.EqualTo(created.GetProperty("requestId").GetString()));
            Assert.That(completed.GetProperty("statusCode").GetInt32(), Is.EqualTo(201));
            Assert.That(completed.GetProperty("principalName").GetString(), Is.EqualTo("sdk"));
            var auditJson = JsonSerializer.Serialize(audit, TestJson);
            foreach (var sensitive in new[] { token, "test-password-for-http-only", "new-test-password-for-http-only", "private-malformed-body", "private-query-value", "秘密", "updated", session.GetProperty("csrfToken").GetString()! })
                Assert.That(auditJson, Does.Not.Contain(sensitive));
        } finally { await app.StopAsync(); store.Dispose(); Directory.Delete(directory, true); }
    }
}
