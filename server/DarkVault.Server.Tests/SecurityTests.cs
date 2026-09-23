using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DarkVault.Client;
using DarkVault.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Data.Sqlite;
using NUnit.Framework;

namespace DarkVault.Server.Tests;

public sealed class SecurityTests {
    private static readonly JsonSerializerOptions TestJson = new(JsonSerializerDefaults.Web);
    [Test]
    public void ProtectedKeyringRejectsMissingWrongAndTamperedKeysAndSurvivesCopy() {
        var directory = Path.Combine(Path.GetTempPath(), "dv-wrapping-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        var wrapping = RandomNumberGenerator.GetBytes(32); var path = Path.Combine(directory, "keys.json");
        try {
            string serverId;
            var metadata = new SecretMetadata(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "test", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, "string");
            EncryptedValue encrypted;
            using (var original = new KeyRing(path, true, wrapping)) { serverId = original.ServerId; encrypted = original.Encrypt("wrapped-test-secret", metadata); original.RotateData(); original.Protect(); }
            var json = File.ReadAllText(path);
            Assert.That(json, Does.Not.Contain("privateKey").And.Not.Contain("activeData"));
            Assert.Throws<CryptographicException>(() => new KeyRing(path, false));
            Assert.Throws<AuthenticationTagMismatchException>(() => new KeyRing(path, false, RandomNumberGenerator.GetBytes(32)));
            var copy = Path.Combine(directory, "backup.json"); File.Copy(path, copy);
            using (var restored = new KeyRing(copy, false, wrapping)) {
                Assert.That(restored.ServerId, Is.EqualTo(serverId));
                Assert.That(restored.Decrypt(encrypted, metadata), Is.EqualTo("wrapped-test-secret"));
            }
            var envelope = JsonSerializer.Deserialize<KeyRing.ProtectedRing>(json, TestJson)!;
            var cipher = Wire.Unbase64(envelope.Ciphertext); cipher[0] ^= 1;
            File.WriteAllText(path, JsonSerializer.Serialize(envelope with { Ciphertext = Wire.Base64(cipher) }, TestJson));
            Assert.Throws<AuthenticationTagMismatchException>(() => new KeyRing(path, false, wrapping));
        } finally { CryptographicOperations.ZeroMemory(wrapping); Directory.Delete(directory, true); }
    }

    [Test]
    public async Task AuditStorageFailurePreventsSecretResponse() {
        await using var host = await Host.Start([]);
        JsonElement Run(string operation, object parameters) => JsonSerializer.SerializeToElement(host.Store.Run(new("test", true), operation, JsonSerializer.SerializeToElement(parameters), Guid.NewGuid().ToString()), TestJson);
        var bucket = Run("bucket.create", new { name = "audit_gate" }).GetProperty("id").GetString();
        Run("secret.create", new { bucket = "audit_gate", key = "private", value = "must-not-be-returned" });
        var token = Run("token.create", new { name = "test", scopes = new[] { "secret:read" }, bucketIds = new[] { bucket }, allBuckets = false, creatableBucketNames = Array.Empty<string>() }).GetProperty("token").GetString();
        using var connection = new SqliteConnection($"Data Source={Path.Combine(host.Directory, "vault.db")};Pooling=False"); connection.Open();
        using var command = connection.CreateCommand(); command.CommandText = "CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'test audit failure'); END;"; command.ExecuteNonQuery();
        using var client = new DarkVaultClient(host.Url, token!, host.Http);
        Assert.ThrowsAsync<DarkVaultException>(async () => await client.ReadSecretAsync("audit_gate", "private"));
    }

    [Test]
    public async Task MfaRequiresSignatureRejectsReplayAndConsumesRecoveryCodeOnce() {
        await using var host = await Host.Start(["--Security:RateLimits:Login=30"]);
        const string password = "mfa-test-password-only";
        host.Store.SetPassword(password);
        host.Http.DefaultRequestHeaders.Add("Origin", host.Url);
        var session = await host.Http.GetFromJsonAsync<JsonElement>(host.Url + "/admin/api/v1/session");
        host.Http.DefaultRequestHeaders.Add("X-CSRF-Token", session.GetProperty("csrfToken").GetString());
        using var authenticator = new TestPasskey();
        using var login = await host.Http.PostAsJsonAsync(host.Url + "/admin/login", new { username = "admin", password });
        var challengeCookies = login.Headers.GetValues("Set-Cookie").ToArray(); Assert.That(challengeCookies.Any(cookie => cookie.StartsWith("__Secure-DarkVault-Mfa=", StringComparison.Ordinal) && cookie.Contains("Path=/admin", StringComparison.OrdinalIgnoreCase)), Is.True); Assert.That(challengeCookies.Any(cookie => cookie.Contains("__Host-", StringComparison.Ordinal)), Is.False);
        var options = await login.Content.ReadFromJsonAsync<JsonElement>();
        var before = await host.Http.GetFromJsonAsync<JsonElement>(host.Url + "/admin/api/v1/session");
        Assert.That(before.GetProperty("authenticated").GetBoolean(), Is.False);
        using var denied = await host.Http.PostAsync(host.Url + "/admin/api/v1/execute", null);
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        var credential = authenticator.Response(host.Url, options);
        using var verified = await host.Http.PostAsJsonAsync(host.Url + "/admin/mfa/verify", new { credential });
        var sessionCookies = verified.Headers.GetValues("Set-Cookie").ToArray(); Assert.That(sessionCookies.Any(cookie => cookie.StartsWith("__Secure-DarkVault=", StringComparison.Ordinal) && cookie.Contains("Path=/admin", StringComparison.OrdinalIgnoreCase)), Is.True);
        Assert.That(verified.IsSuccessStatusCode, Is.True, await verified.Content.ReadAsStringAsync());
        var codes = (await verified.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("recoveryCodes");
        var recovery = codes[0].GetString();
        Assert.That(codes.GetArrayLength(), Is.EqualTo(8));
        using var replay = await host.Http.PostAsJsonAsync(host.Url + "/admin/mfa/verify", new { credential });
        Assert.That(replay.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        using var again = await host.Http.PostAsJsonAsync(host.Url + "/admin/login", new { username = "admin", password });
        options = await again.Content.ReadFromJsonAsync<JsonElement>();
        using var foreign = await host.Http.PostAsJsonAsync(host.Url + "/admin/mfa/verify", new { credential = authenticator.Response("https://evil.example", options) });
        Assert.That(foreign.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        using var consumed = await host.Http.PostAsJsonAsync(host.Url + "/admin/mfa/verify", new { credential = authenticator.Response(host.Url, options) });
        Assert.That(consumed.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        using var recover = await host.Http.PostAsJsonAsync(host.Url + "/admin/login", new { username = "admin", password, recoveryCode = recovery });
        Assert.That(recover.IsSuccessStatusCode, Is.True);
        using var reusedCode = await host.Http.PostAsJsonAsync(host.Url + "/admin/login", new { username = "admin", password, recoveryCode = recovery });
        Assert.That(reusedCode.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(JsonSerializer.Serialize(host.Store.Mfa), Does.Not.Contain(recovery));
        using var replacement = new TestPasskey();
        await replacement.Finish(host.Http, host.Url, recover);
        Assert.That(host.Store.Mfa.Passkeys, Has.Length.EqualTo(1));
    }

    [Test]
    public void TokensHaveDefaultExpiryAndRejectExcessiveLifetime() {
        var directory = Path.Combine(Path.GetTempPath(), "dv-expiry-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        try {
            var ring = new KeyRing(Path.Combine(directory, "keys.json"), true);
            using var store = new VaultStore(Path.Combine(directory, "vault.db"), ring);
            object Create(DateTimeOffset? expiresAt) => store.Run(new("test", true), "token.create", JsonSerializer.SerializeToElement(new {
                name = "expiry",
                scopes = Array.Empty<string>(),
                bucketIds = Array.Empty<string>(),
                allBuckets = false,
                creatableBucketNames = Array.Empty<string>(),
                expiresAt
            }), Guid.NewGuid().ToString());
            var issued = JsonSerializer.SerializeToElement(Create(null), TestJson);
            var principal = store.Authenticate(issued.GetProperty("token").GetString()!);
            Assert.That(principal.Token!.ExpiresAt, Is.InRange(DateTimeOffset.UtcNow.AddDays(29), DateTimeOffset.UtcNow.AddDays(31)));
            var yearlyExpiry = DateTimeOffset.UtcNow.AddYears(1);
            var yearly = JsonSerializer.SerializeToElement(Create(yearlyExpiry), TestJson);
            var yearlyPrincipal = store.Authenticate(yearly.GetProperty("token").GetString()!);
            Assert.That(yearlyPrincipal.Token!.ExpiresAt, Is.EqualTo(yearlyExpiry));
            var listed = JsonSerializer.SerializeToElement(store.Run(new("test", true), "token.list", JsonSerializer.SerializeToElement(new { }), Guid.NewGuid().ToString()), TestJson);
            Assert.That(listed.GetProperty("items").EnumerateArray().Single(t => t.GetProperty("info").GetProperty("id").GetString() == yearlyPrincipal.Id).GetProperty("info").GetProperty("expiresAt").GetDateTimeOffset(), Is.EqualTo(yearlyExpiry));
            Assert.Throws<VaultFault>(() => Create(DateTimeOffset.UtcNow.AddYears(1).AddMinutes(1)));
            Assert.Throws<VaultFault>(() => Create(DateTimeOffset.UtcNow.AddMinutes(-1)));
        } finally { Directory.Delete(directory, true); }
    }

    [Test]
    public void BansExpireEscalateAndCannotGrowWithoutBound() {
        var time = new Clock(); var protection = new AbuseProtection(time);
        var ip = IPAddress.Parse("192.0.2.1");
        for (var i = 0; i < 10; i++) protection.Failed(ip, true);
        Assert.That(protection.RetryAfter(ip), Is.EqualTo(900));
        Assert.That(protection.RetryAfter(IPAddress.Parse("192.0.2.2")), Is.Zero);
        time.Now += TimeSpan.FromMinutes(15);
        Assert.That(protection.RetryAfter(ip), Is.Zero);
        for (var i = 0; i < 10; i++) protection.Failed(ip, true);
        Assert.That(protection.RetryAfter(ip), Is.EqualTo(1800));
        time.Now += TimeSpan.FromDays(2);
        var activeBan = IPAddress.Parse("192.0.2.3");
        for (var i = 0; i < 60; i++) protection.Failed(activeBan, false);
        Assert.That(protection.RetryAfter(activeBan), Is.EqualTo(900));
        for (var i = 0; i < AbuseProtection.Capacity - 1; i++)
            protection.Failed(new IPAddress(new byte[] { 10, (byte)(i >> 8), (byte)i, 1 }), false);
        var newcomer = IPAddress.Parse("203.0.113.10");
        Assert.That(protection.RetryAfter(newcomer), Is.Zero);
        for (var i = 0; i < 60; i++) protection.Failed(newcomer, false);
        Assert.That(protection.RetryAfter(newcomer), Is.EqualTo(900));
        Assert.That(protection.RetryAfter(activeBan), Is.EqualTo(900));
    }

    [Test]
    public void AddressNormalizationPreventsIpv6RotationAndMappedIpv4Bypasses() {
        Assert.That(SecurityLimits.AddressKey(IPAddress.Parse("::ffff:192.0.2.1")), Is.EqualTo("192.0.2.1"));
        Assert.That(SecurityLimits.AddressKey(IPAddress.Parse("2001:db8:1:2::1")), Is.EqualTo(SecurityLimits.AddressKey(IPAddress.Parse("2001:db8:1:2::abcd"))));
        var protection = new AbuseProtection(new Clock());
        for (var i = 0; i < 60; i++) protection.Failed(IPAddress.Parse("2001:db8:1:2::1"), false);
        Assert.That(protection.RetryAfter(IPAddress.Parse("2001:db8:1:2::abcd")), Is.EqualTo(900));
    }

    [Test]
    public void GlobalQuotaAndIndependentLoginAndPrincipalQuotasAreEnforced() {
        using var limits = new SecurityLimits(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Security:RateLimits:Global"] = "3",
            ["Security:RateLimits:Admission"] = "3",
            ["Security:RateLimits:Login"] = "1",
            ["Security:RateLimits:Principal"] = "1"
        }).Build());
        for (var i = 0; i < 3; i++) {
            var context = new DefaultHttpContext(); context.Connection.RemoteIpAddress = IPAddress.Parse($"192.0.2.{i + 1}");
            using var lease = limits.Network.AttemptAcquire(context); Assert.That(lease.IsAcquired, Is.True);
        }
        using var denied = limits.Network.AttemptAcquire(new DefaultHttpContext()); Assert.That(denied.IsAcquired, Is.False);
        Assert.That(SecurityLimits.RetryAfter(denied), Is.InRange(1, 60));
        for (var i = 0; i < 3; i++) { using var lease = limits.AnonymousRequests.AttemptAcquire(); Assert.That(lease.IsAcquired, Is.True); }
        using var anonymousDenied = limits.AnonymousRequests.AttemptAcquire(); Assert.That(anonymousDenied.IsAcquired, Is.False);
        for (var i = 0; i < 3; i++) { using var lease = limits.AuthenticatedRequests.AttemptAcquire(); Assert.That(lease.IsAcquired, Is.True); }
        using var authenticatedDenied = limits.AuthenticatedRequests.AttemptAcquire(); Assert.That(authenticatedDenied.IsAcquired, Is.False);
        using var first = limits.Logins.AttemptAcquire("a"); using var same = limits.Logins.AttemptAcquire("a"); using var other = limits.Logins.AttemptAcquire("b");
        Assert.That(first.IsAcquired && !same.IsAcquired && other.IsAcquired, Is.True);
        using var token = limits.Principals.AttemptAcquire("token:a"); using var retry = limits.Principals.AttemptAcquire("token:a");
        Assert.That(token.IsAcquired && !retry.IsAcquired, Is.True);
    }

    [Test]
    public async Task UntrustedForwardedHeadersCannotBypassLimitsAndThrottlingPrecedesDatabaseAccess() {
        await using var host = await Host.Start(["--Security:RateLimits:Ip=2", "--DARKVAULT_TRUSTED_PROXIES="]);
        for (var i = 0; i < 2; i++) {
            using var request = new HttpRequestMessage(HttpMethod.Get, host.Url + "/api/v1/crypto/key");
            request.Headers.Add("X-Forwarded-For", $"198.51.100.{i + 1}");
            using var response = await host.Http.SendAsync(request); Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        host.Store.Dispose();
        using var attack = new HttpRequestMessage(HttpMethod.Post, host.Url + "/api/v1/execute");
        attack.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Wire.NewToken());
        attack.Headers.Add("X-Forwarded-For", "198.51.100.99");
        using var denied = await host.Http.SendAsync(attack);
        Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
        Assert.That(denied.Headers.RetryAfter?.Delta, Is.GreaterThan(TimeSpan.Zero));
    }

    [Test]
    public async Task AnonymousTrafficCannotExhaustTheAuthenticatedBudget() {
        await using var host = await Host.Start(["--Security:RateLimits:Global=2"]);
        var token = JsonSerializer.SerializeToElement(host.Store.Run(new("test", true), "token.create", JsonSerializer.SerializeToElement(new {
            name = "budget",
            scopes = Array.Empty<string>(),
            bucketIds = Array.Empty<string>(),
            allBuckets = false,
            creatableBucketNames = Array.Empty<string>()
        }), Guid.NewGuid().ToString()), TestJson).GetProperty("token").GetString();
        for (var i = 0; i < 3; i++) {
            using var anonymous = await host.Http.GetAsync(host.Url + "/api/v1/crypto/key");
            Assert.That(anonymous.StatusCode, Is.EqualTo(i < 2 ? HttpStatusCode.OK : HttpStatusCode.TooManyRequests));
        }
        using var ready = await host.Http.GetAsync(host.Url + "/health/ready");
        Assert.That(ready.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        for (var i = 0; i < 2; i++) {
            using var request = new HttpRequestMessage(HttpMethod.Post, host.Url + "/api/v1/execute");
            request.Headers.Authorization = new("Bearer", token);
            // An empty body passes admission and fails later as an invalid envelope, not as rate limited.
            using var response = await host.Http.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
    }

    [Test]
    public async Task UnexpectedFailuresAreUnavailableRatherThanInvalidRequests() {
        await using var host = await Host.Start([]);
        host.Store.Dispose();
        using var request = new HttpRequestMessage(HttpMethod.Post, host.Url + "/api/v1/execute");
        request.Headers.Authorization = new("Bearer", Wire.NewToken());
        using var response = await host.Http.SendAsync(request);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
        var error = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(error.GetProperty("error").GetProperty("code").GetString(), Is.EqualTo("unavailable"));
    }

    [Test]
    public async Task PrincipalQuotaFollowsTokenAcrossTrustedSourceAddresses() {
        await using var host = await Host.Start(["--Security:RateLimits:Principal=2", "--DARKVAULT_TRUSTED_PROXIES=127.0.0.1"]);
        var result = JsonSerializer.SerializeToElement(host.Store.Run(new("test", true), "token.create", JsonSerializer.SerializeToElement(new {
            name = "limited",
            scopes = Array.Empty<string>(),
            bucketIds = Array.Empty<string>(),
            allBuckets = false,
            creatableBucketNames = Array.Empty<string>()
        }), Guid.NewGuid().ToString()), TestJson);
        var token = result.GetProperty("token").GetString();
        for (var i = 0; i < 3; i++) {
            using var request = new HttpRequestMessage(HttpMethod.Post, host.Url + "/api/v1/execute");
            request.Headers.Authorization = new("Bearer", token); request.Headers.Add("X-Forwarded-For", $"198.51.100.{i + 1}");
            using var response = await host.Http.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(i == 2 ? HttpStatusCode.TooManyRequests : HttpStatusCode.BadRequest));
        }
    }

    [Test]
    public async Task InvalidTokensCauseApplicationBanWithoutWritingAnonymousAudit() {
        await using var host = await Host.Start(["--DARKVAULT_TRUSTED_PROXIES="]);
        for (var i = 0; i < 61; i++) {
            using var request = new HttpRequestMessage(HttpMethod.Post, host.Url + "/api/v1/execute");
            request.Headers.Authorization = new("Bearer", Wire.NewToken());
            using var response = await host.Http.SendAsync(request);
            Assert.That(response.StatusCode, Is.EqualTo(i == 60 ? HttpStatusCode.TooManyRequests : HttpStatusCode.Unauthorized));
            if (i == 60) Assert.That(response.Headers.RetryAfter?.Delta, Is.GreaterThan(TimeSpan.FromMinutes(14)));
        }
        await host.App.StopAsync();
        var audit = JsonSerializer.SerializeToElement(host.Store.Run(new("test", true), "audit.list", JsonSerializer.SerializeToElement(new { limit = 200 }), Guid.NewGuid().ToString()), TestJson);
        Assert.That(audit.GetProperty("items").EnumerateArray().Any(e => e.GetProperty("kind").GetString() == "http"), Is.False);
    }

    private sealed class Clock : TimeProvider {
        public DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Test]
    public async Task AdminCredentialBodiesHaveASeparateBoundedLimit() {
        await using var host = await Host.Start([]);
        host.Http.DefaultRequestHeaders.Add("Origin", host.Url);
        var session = await host.Http.GetFromJsonAsync<JsonElement>(host.Url + "/admin/api/v1/session");
        host.Http.DefaultRequestHeaders.Add("X-CSRF-Token", session!.GetProperty("csrfToken").GetString());
        using var body = new StringContent(new string('x', 70 * 1024), Encoding.UTF8, "application/json");
        using var response = await host.Http.PostAsync(host.Url + "/admin/login", body);
        Assert.That((int)response.StatusCode, Is.EqualTo(413));
    }

    [Test]
    public async Task ProxiedHostIsRejectedWithoutACanonicalPublicOrigin() {
        const string password = "origin-test-password-only";
        const string proxied = "vault.example.com";
        foreach (var configured in new[] { null, "https://" + proxied }) {
            string[] arguments = configured is null ? ["--Security:RateLimits:Login=30"] : ["--Security:RateLimits:Login=30", "--DARKVAULT_PUBLIC_ORIGIN=" + configured];
            await using var host = await Host.Start(arguments);
            host.Store.SetPassword(password);
            // A misconfigured proxy can forward any Host; only a canonical origin may define the WebAuthn origin.
            host.Http.DefaultRequestHeaders.Host = proxied;
            host.Http.DefaultRequestHeaders.Add("Origin", "https://" + proxied);
            var session = await host.Http.GetFromJsonAsync<JsonElement>(host.Url + "/admin/api/v1/session");
            host.Http.DefaultRequestHeaders.Add("X-CSRF-Token", session.GetProperty("csrfToken").GetString());
            using var login = await host.Http.PostAsJsonAsync(host.Url + "/admin/login", new { username = "admin", password });
            if (configured is null) {
                Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
                var error = await login.Content.ReadFromJsonAsync<JsonElement>();
                Assert.That(error.GetProperty("error").GetProperty("code").GetString(), Is.EqualTo("invalid_origin"));
            } else {
                Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            }
        }
    }

    [Test, NonParallelizable]
    public async Task WrappingKeyIsRefusedInsideTheDataDirectory() {
        var directory = Path.Combine(Path.GetTempPath(), "dv-wrapping-command-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        var previous = Environment.GetEnvironmentVariable("DARKVAULT_DATA");
        Environment.SetEnvironmentVariable("DARKVAULT_DATA", directory);
        var outside = Path.Combine(Path.GetTempPath(), "dv-wrapping-command-" + Guid.NewGuid() + ".key");
        try {
            var inside = Path.Combine(directory, "wrapping.key");
            Assert.That(await ServerCommands.RunAsync(["create-wrapping-key", inside]), Is.EqualTo(1));
            Assert.That(File.Exists(inside), Is.False);
            Assert.That(await ServerCommands.RunAsync(["create-wrapping-key", outside]), Is.EqualTo(0));
            Assert.That(File.Exists(outside), Is.True);
        } finally {
            Environment.SetEnvironmentVariable("DARKVAULT_DATA", previous);
            File.Delete(outside); System.IO.Directory.Delete(directory, true);
        }
    }
    private sealed class Host : IAsyncDisposable {
        private readonly string directory;
        public string Directory => directory;
        private readonly X509Certificate2 certificate;
        public WebApplication App { get; }
        public VaultStore Store { get; }
        public HttpClient Http { get; }
        public string Url => App.Urls.Single();
        private Host(string[] args) {
            directory = Path.Combine(Path.GetTempPath(), "dv-security-" + Guid.NewGuid()); System.IO.Directory.CreateDirectory(directory);
            using var rsa = RSA.Create(2048);
            certificate = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            var ring = new KeyRing(Path.Combine(directory, "keys.json"), true);
            Store = new(Path.Combine(directory, "vault.db"), ring);
            App = VaultApplication.Build(args, Store, ring, directory);
            App.Urls.Add("https://127.0.0.1:0");
            var certFile = Path.Combine(directory, "test.pfx"); File.WriteAllBytes(certFile, certificate.Export(X509ContentType.Pfx));
            App.Configuration["Kestrel:Certificates:Default:Path"] = certFile;
            Http = new(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.Thumbprint == certificate.Thumbprint });
        }
        public static async Task<Host> Start(string[] args) { var host = new Host(args); try { await host.App.StartAsync(); return host; } catch { await host.DisposeAsync(); throw; } }
        public async ValueTask DisposeAsync() { Http.Dispose(); await App.StopAsync(); await App.DisposeAsync(); Store.Dispose(); certificate.Dispose(); System.IO.Directory.Delete(directory, true); }
    }
}
