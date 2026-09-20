using System.Security.Cryptography;
using System.Text.Json;
using DarkVault.Client;
using NUnit.Framework;

namespace DarkVault.Client.Tests;

public sealed class ProtocolFixtureTests {
    [Test]
    public void RequiredProtocolFieldsCannotBeMissingOrNull() {
        Assert.Throws<JsonException>(() => Wire.Parse<PublicKey>("{\"kty\":\"EC\",\"crv\":\"P-256\"}"));
        Assert.Throws<JsonException>(() => Wire.Parse<PublicKey>("{\"kty\":null,\"crv\":\"P-256\",\"x\":\"a\",\"y\":\"b\"}"));
    }
    [Test]
    public void PublishedFixtureMatchesDotNet() {
        using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(TestContext.CurrentContext.TestDirectory, "fixtures", "jwe.json")));
        var f = fixture.RootElement; var jwk = f.GetProperty("jwk");
        using var key = ECDsa.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = Wire.Unbase64(jwk.GetProperty("d").GetString()!),
            Q = new ECPoint { X = Wire.Unbase64(jwk.GetProperty("x").GetString()!), Y = Wire.Unbase64(jwk.GetProperty("y").GetString()!) }
        });
        Assert.That(Wire.Decrypt(f.GetProperty("compact").GetString()!, key, f.GetProperty("kid").GetString()!, f.GetProperty("type").GetString()!), Is.EqualTo(f.GetProperty("plaintext").GetString()));
        Assert.That(Wire.HashToken(f.GetProperty("token").GetString()!), Is.EqualTo(f.GetProperty("tokenHash").GetString()));
    }
    [Test]
    public void JweRoundTripAndTamperingAreRejected() {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var body = Wire.Encrypt("{\"value\":\"秘密\"}", Wire.Export(key), "test", "darkvault-response+jwe");
        Assert.That(Wire.Decrypt(body, key, "test", "darkvault-response+jwe"), Does.Contain("秘密"));
        var parts = body.Split('.'); var tag = Wire.Unbase64(parts[4]); tag[0] ^= 1; parts[4] = Wire.Base64(tag);
        Assert.Catch(() => Wire.Decrypt(string.Join('.', parts), key, "test", "darkvault-response+jwe"));
        Assert.Catch(() => Wire.Decrypt(body, key, "other", "darkvault-response+jwe"));
        Assert.Catch(() => Wire.Decrypt(body, key, "test", "darkvault-request+jwe"));
    }
    [Test]
    public void CompactJweRemainsCompatibleWithTheJoseJwtCodec() {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string plaintext = "{\"value\":\"秘密\\nvalue\"}";
        var compact = Wire.Encrypt(plaintext, Wire.Export(key), "test", "darkvault-response+jwe");
        Assert.That(Jose.JWT.Decode(compact, key, Jose.JweAlgorithm.ECDH_ES, Jose.JweEncryption.A256GCM), Is.EqualTo(plaintext));
        var reference = Jose.JWT.Encode(plaintext, key, Jose.JweAlgorithm.ECDH_ES, Jose.JweEncryption.A256GCM,
            extraHeaders: new Dictionary<string, object> { ["kid"] = "test", ["typ"] = "darkvault-response+jwe", ["cty"] = "application/json" });
        Assert.That(Wire.Decrypt(reference, key, "test", "darkvault-response+jwe"), Is.EqualTo(plaintext));
        var parts = compact.Split('.');
        parts[0] = Wire.Base64(System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(Wire.Unbase64(parts[0])).Replace("test", "changed")));
        Assert.Catch(() => Wire.Decrypt(string.Join('.', parts), key, "changed", "darkvault-response+jwe"));
    }
    [Test]
    public void JsonRejectsDuplicateUnknownAndIncorrectlyCasedFields() {
        Assert.Throws<FormatException>(() => Wire.ValidateJson("{\"a\":1,\"a\":2}"));
        Assert.Throws<JsonException>(() => Wire.Parse<PublicKey>("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\",\"y\":\"\",\"d\":\"private\"}"));
        Assert.Throws<JsonException>(() => Wire.Parse<PublicKey>("{\"Kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\",\"y\":\"\"}"));
    }
}
