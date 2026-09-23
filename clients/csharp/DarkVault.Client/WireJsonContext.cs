using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;

#if DARKVAULT_SERVER
namespace DarkVault.Server;
#else
namespace DarkVault.Client;
#endif

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(PublicKey))]
[JsonSerializable(typeof(CryptoKey))]
[JsonSerializable(typeof(TransportLimits))]
[JsonSerializable(typeof(VaultRequest))]
[JsonSerializable(typeof(VaultResponse))]
[JsonSerializable(typeof(Bucket))]
[JsonSerializable(typeof(Secret))]
[JsonSerializable(typeof(SecretMetadata))]
[JsonSerializable(typeof(BucketSnapshot))]
[JsonSerializable(typeof(TokenInfo))]
[JsonSerializable(typeof(Page<Bucket>))]
[JsonSerializable(typeof(Page<SecretMetadata>))]
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(bool))]
internal partial class WireJsonContext : JsonSerializerContext;
