using System.Net;
using DarkVault.Client;
using NUnit.Framework;

namespace DarkVault.Client.Tests;

public sealed class ConnectionStringTests {
    [Test]
    public async Task ConnectionStringsValidateAndKeepCredentialsOutOfRequestUrls() {
        var token = "dv1_" + new string('A', 60);
        foreach (var host in new[] { "vault.example.com", "localhost:8443", "[::1]:8443" }) {
            using var http = new HttpClient(new OriginHandler("https://" + host + "/api/v1/crypto/key"));
            using var client = DarkVaultClient.FromUrl("https://" + token + "@" + host + "/qa", http);
            Assert.That(client.DefaultBucket, Is.EqualTo("qa"));
            try { await client.ReadBucketAsync(); Assert.Fail("Expected discovery failure."); } catch (DarkVaultException) { }
        }
        foreach (var raw in new[] {
            "http://TOKEN@vault.example.com/qa",
            "https://vault.example.com/qa",
            "https://TOKEN:password@vault.example.com/qa",
            "https://TOKEN@vault.example.com",
            "https://TOKEN@vault.example.com/",
            "https://TOKEN@vault.example.com/qa/",
            "https://TOKEN@vault.example.com/a/../qa",
            "https://TOKEN@vault.example.com/qa?x=1",
            "https://TOKEN@vault.example.com/qa#x",
            "https://TOKEN@vault.example.com/qa\n",
            "https://TOKEN@vault.example.com:0/qa",
            "https://TOKEN@vault.example.com:65536/qa",
            "https://TOKEN@[bad/qa",
            "https://TOKEN@/qa",
            "https://TOKEN@vault.example.com/UPPER",
            "https://TOKEN@vault.example.com/%71a",
            "https://bad@vault.example.com/qa"
        }) {
            var error = Assert.Throws<ArgumentException>(() => DarkVaultClient.FromUrl(raw.Replace("TOKEN", token)));
            Assert.That(error!.ToString(), Does.Not.Contain(token));
        }
        using var legacy = new DarkVaultClient("vault.example.com", token);
        Assert.Throws<InvalidOperationException>(() => legacy.ReadBucketSnapshotAsync());
    }

    private sealed class OriginHandler(string expected) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            Assert.That(request.RequestUri!.AbsoluteUri, Is.EqualTo(expected));
            Assert.That(request.Headers.Authorization, Is.Null);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest) { RequestMessage = request });
        }
    }
}
