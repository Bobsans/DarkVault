# DarkVault.Client

.NET 10 client for DarkVault HTTP API. Uses HTTPS and ECDH-ES/P-256/A256GCM JWE.

```csharp
using DarkVault.Client;

using var client = new DarkVaultClient("https://vault.example.com", token);
var secrets = await client.ReadBucketAsync("app_qa", cancellationToken);
```

Provide the token from your application's secret source. It must be exactly 64 characters.
Bucket reads require bucket:read, secret:read, secret:list and an explicit bucket grant.
CRUD methods are asynchronous and accept CancellationToken. Updates/deletes require the
revision obtained from a previous read; a conflict never overwrites newer data silently.

Reuse the client. An optional externally owned HttpClient must disable redirects and retain
TLS certificate verification. Default request deadline is 30 seconds. Mutations are not
automatically retried after uncertain network failures. Inspect DarkVaultException.Code,
Status and RequestId; never log secret values or authorization headers.

For ASP.NET Core configuration, use DarkVault.Extensions.Configuration.
