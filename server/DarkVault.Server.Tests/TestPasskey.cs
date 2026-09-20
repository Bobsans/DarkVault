using System.Buffers.Binary;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarkVault.Client;
using NUnit.Framework;

namespace DarkVault.Server.Tests;

// Synthetic authenticator used only by HTTPS tests. Production verification is .NET WebAuthn.
internal sealed class TestPasskey : IDisposable {
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] id = RandomNumberGenerator.GetBytes(32);
    private uint count;
    private string? handle;
    public async Task<JsonElement> Finish(HttpClient http, string origin, HttpResponseMessage optionsResponse) {
        optionsResponse.EnsureSuccessStatusCode();
        var options = await optionsResponse.Content.ReadFromJsonAsync<JsonElement>();
        var body = Response(origin, options);
        using var response = await http.PostAsJsonAsync(origin + "/admin/mfa/verify", new { credential = body });
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.That(response.IsSuccessStatusCode, Is.True, result.ToString());
        return result;
    }
    public JsonElement Response(string origin, JsonElement envelope) {
        var register = envelope.GetProperty("mode").GetString() == "register";
        var options = envelope.GetProperty("options");
        var client = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { type = register ? "webauthn.create" : "webauthn.get", challenge = options.GetProperty("challenge").GetString(), origin, crossOrigin = false }));
        var rp = register ? options.GetProperty("rp").GetProperty("id").GetString()! : options.GetProperty("rpId").GetString()!;
        var auth = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(rp))) { (byte)(register ? 0x45 : 0x05) };
        var counter = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(counter, register ? 0 : ++count); auth.AddRange(counter);
        object response;
        if (register) {
            handle = options.GetProperty("user").GetProperty("id").GetString();
            auth.AddRange(new byte[16]); auth.AddRange(new byte[] { 0, (byte)id.Length }); auth.AddRange(id);
            var publicKey = key.ExportParameters(false);
            auth.AddRange(new byte[] { 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 });
            auth.AddRange(publicKey.Q.X!); auth.AddRange(new byte[] { 0x22, 0x58, 0x20 }); auth.AddRange(publicKey.Q.Y!);
            var attestation = new List<byte> { 0xa3, 0x63 }; attestation.AddRange(Encoding.ASCII.GetBytes("fmt"));
            attestation.Add(0x64); attestation.AddRange(Encoding.ASCII.GetBytes("none"));
            attestation.Add(0x67); attestation.AddRange(Encoding.ASCII.GetBytes("attStmt")); attestation.Add(0xa0);
            attestation.Add(0x68); attestation.AddRange(Encoding.ASCII.GetBytes("authData"));
            attestation.Add(0x58); attestation.Add((byte)auth.Count); attestation.AddRange(auth);
            response = new { clientDataJSON = Wire.Base64(client), attestationObject = Wire.Base64(attestation.ToArray()), transports = new[] { "usb" } };
        } else {
            var signature = key.SignData(auth.Concat(SHA256.HashData(client)).ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            response = new { clientDataJSON = Wire.Base64(client), authenticatorData = Wire.Base64(auth.ToArray()), signature = Wire.Base64(signature), userHandle = handle };
        }
        return JsonSerializer.SerializeToElement(new { id = Wire.Base64(id), rawId = Wire.Base64(id), type = "public-key", response, clientExtensionResults = new { } });
    }
    public void Dispose() => key.Dispose();
}
