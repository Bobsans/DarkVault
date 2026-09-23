using System.Net;
using System.Security.Cryptography;
using System.Text;
using DarkVault.Client;
using NUnit.Framework;

namespace DarkVault.Client.Tests;

public sealed class TransportTests {
    private const string Token = "dv1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private static string ServerKey() {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Wire.Serialize(new CryptoKey(1, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow, Guid.NewGuid().ToString(), Wire.Export(key),
            DateTimeOffset.UtcNow.AddMinutes(5), new TransportLimits(Wire.MaxBody, Wire.MaxPlaintext)));
    }

    private static HttpResponseMessage Json(HttpRequestMessage request, HttpStatusCode status, string body) =>
        new(status) { RequestMessage = request, Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static (DarkVaultClient Client, Func<int> Posts) Client(Func<HttpRequestMessage, HttpResponseMessage> execute) {
        var key = ServerKey(); var posts = 0;
        var http = new HttpClient(new Handler(request => {
            if (request.RequestUri!.AbsolutePath == "/api/v1/crypto/key") return Json(request, HttpStatusCode.OK, key);
            posts++; return execute(request);
        }));
        return (new DarkVaultClient("https://vault.example.com", Token, http), () => posts);
    }

    [Test]
    public void RetryAfterBeyondTheDeadlineFailsImmediatelyWithTheServerCode() {
        var (client, posts) = Client(request => {
            var response = Json(request, HttpStatusCode.TooManyRequests, """{"error":{"code":"rate_limited","message":"slow down"}}""");
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(60));
            return response;
        });
        using (client) {
            var started = System.Diagnostics.Stopwatch.StartNew();
            var error = Assert.ThrowsAsync<DarkVaultException>(async () => await client.ReadBucketAsync("qa"));
            Assert.That((error!.Code, error.Status, error.RetryAfter, posts()), Is.EqualTo(("rate_limited", 429, (TimeSpan?)TimeSpan.FromSeconds(60), 1)));
            Assert.That(started.Elapsed, Is.LessThan(TimeSpan.FromSeconds(5)));
        }
    }

    [Test]
    public void BrokenResponseStreamsRetryReadsAndReportWritesAsUnknown() {
        var (reader, readPosts) = Client(_ => throw new IOException("connection reset"));
        using (reader) {
            var error = Assert.ThrowsAsync<DarkVaultException>(async () => await reader.ReadBucketAsync("qa"));
            Assert.That((error!.Code, readPosts()), Is.EqualTo(("unavailable", 3)));
        }
        var (writer, writePosts) = Client(_ => throw new IOException("connection reset"));
        using (writer) {
            var error = Assert.ThrowsAsync<DarkVaultException>(async () => await writer.AddBucketAsync("qa"));
            Assert.That((error!.Code, writePosts()), Is.EqualTo(("outcome_unknown", 1)));
        }
    }

    [Test]
    public void DiscoveryFailuresBeforeAWriteAreRetriedAndNeverReportedAsUnknown() {
        var discoveries = 0;
        using var http = new HttpClient(new Handler(request => {
            discoveries++;
            throw new HttpRequestException("connection refused");
        }));
        using var client = new DarkVaultClient("https://vault.example.com", Token, http);
        var error = Assert.ThrowsAsync<DarkVaultException>(async () => await client.AddBucketAsync("qa"));
        Assert.That((error!.Code, discoveries), Is.EqualTo(("unavailable", 3)));
    }

    [Test]
    public void DiscoveryRedirectIsRejected() {
        using var http = new HttpClient(new Handler(request => {
            var response = new HttpResponseMessage(HttpStatusCode.Found) { RequestMessage = request };
            response.Headers.Location = new Uri("https://evil.example.com/");
            return response;
        }));
        using var client = new DarkVaultClient("https://vault.example.com", Token, http);
        var error = Assert.ThrowsAsync<DarkVaultException>(async () => await client.GetTokenInfoAsync());
        Assert.That((error!.Code, error.Status), Is.EqualTo(("redirect_rejected", 302)));
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
