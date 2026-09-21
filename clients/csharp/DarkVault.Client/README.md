# DarkVault.Client

[![NuGet](https://img.shields.io/nuget/v/DarkVault.Client)](https://www.nuget.org/packages/DarkVault.Client)
[![.NET 10](https://img.shields.io/badge/runtime-.NET%2010-blue)](https://github.com/Bobsans/DarkVault)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

The asynchronous .NET SDK for DarkVault buckets, secrets, and token metadata.
Load application configuration or manage individual secrets with revision checks.

## Install

```sh
dotnet add package DarkVault.Client
```

Targets .NET 10. For ASP.NET Core configuration, use
[DarkVault.Extensions.Configuration](https://github.com/Bobsans/DarkVault/blob/main/clients/csharp/DarkVault.Extensions.Configuration/README.md).

## Quick start

```csharp
using DarkVault.Client;

var token = Environment.GetEnvironmentVariable("DARKVAULT_TOKEN")
    ?? throw new InvalidOperationException("DARKVAULT_TOKEN is required");

using var vault = new DarkVaultClient("https://vault.example.com", token);
using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

var settings = await vault.ReadBucketAsync("app_prod", timeout.Token);
var databaseUrl = settings["Database:Url"];
```

Reuse a client and dispose it when its owner shuts down. The client disposes its
own HTTP client but never a caller-supplied one.

## Connection and permissions

Use the server's HTTPS origin, for example `https://vault.example.com`, without an
API path, URL credentials, query, or fragment. Tokens are issued in the DarkVault
web UI and use the `dv1_` format (64 characters total). Supply the token explicitly
from a protected source; this SDK does not load CLI configuration.

Bucket arguments are exact names, not UUIDs. Each operation needs its matching
token scopes and bucket access. Reading an entire bucket needs `bucket:read`,
`secret:read`, and `secret:list`. Bucket creation additionally depends on the
token's allowed creation names. Token issuance and revocation are administrative
operations, not SDK methods.

Values are strings. Treat returned secrets as sensitive in-memory data; do not
log values, Authorization headers, or request bodies. TLS verification must stay
enabled. JWE uses ECDH-ES/P-256/A256GCM in addition to HTTPS; the server still sees
plaintext secrets, so this is not a zero-knowledge system.

## Required scopes

| Operation | Required scopes |
| --- | --- |
| List buckets | `bucket:list` |
| Get bucket metadata | `bucket:read` |
| Read bucket values | `bucket:read`, `secret:read`, `secret:list` |
| Create bucket | `bucket:create` |
| Update bucket description | `bucket:write` |
| Delete empty bucket | `bucket:delete` |
| Delete bucket recursively | `bucket:delete`, `secret:delete` |
| List secret metadata | `secret:list` |
| Read secret value | `secret:read` |
| Create, update, or set secret | `secret:write` |
| Delete secret | `secret:delete` |
| Inspect own token | Any valid token |

Scopes do not replace bucket grants.

## API reference

All operations are asynchronous. Every method below accepts a final optional
`CancellationToken cancellationToken = default`. Results in the table are wrapped
in `Task<T>`; delete methods return `Task`.

| Method (excluding cancellation token) | Result |
| --- | --- |
| `AddBucketAsync(name, description = "")` | `Bucket` |
| `GetBucketAsync(bucket)` | `Bucket` |
| `ListBucketsAsync(cursor = null, limit = 100)` | `Page<Bucket>` |
| `ReadBucketAsync(bucket)` | `IReadOnlyDictionary<string, string?>` |
| `ReadBucketSnapshotAsync(bucket)` | `BucketSnapshot` |
| `UpdateBucketAsync(bucket, description, expectedRevision)` | `Bucket` |
| `RenameBucketAsync(bucket, name, expectedRevision)` | `Bucket` |
| `DeleteBucketAsync(bucket, expectedRevision, recursive = false)` | No value |
| `AddSecretAsync(bucket, key, value)` | `SecretMetadata` |
| `ReadSecretAsync(bucket, key)` | `Secret` |
| `ListSecretsAsync(bucket, cursor = null, limit = 100)` | `Page<SecretMetadata>` |
| `UpdateSecretAsync(bucket, key, value, expectedRevision)` | `SecretMetadata` |
| `SetSecretAsync(bucket, key, value, expectedRevision = 0)` | `SecretMetadata` |
| `DeleteSecretAsync(bucket, key, expectedRevision)` | No value |
| `GetTokenInfoAsync()` | `TokenInfo` |
| `ExecuteAsync<T>(operation, parameters)` | Deserialized `T`; advanced wire API |

Names, keys, values, and descriptions are strings; revisions are `long`, limits
are `int`, and cursors are nullable strings.

- `Bucket`: `Id`, `Name`, `Description`, `Revision`, `CreatedAt`, `UpdatedAt`.
- `SecretMetadata`: `Id`, `BucketId`, `Key`, `Revision`, `CreatedAt`, `UpdatedAt`.
- `Secret`: the same fields plus `Value`. Listing does not return values.
- `BucketSnapshot`: `BucketId`, `Revision`, `Secrets`.
- `Page<T>`: `Items`, `NextCursor`.
- `TokenInfo`: `Id`, `Name`, `Scopes`, `BucketIds`, `AllBuckets`,
  `CreatableBucketNames`, and nullable `ExpiresAt`.

Timestamps use `DateTimeOffset`. Bucket dictionaries preserve secret names.

## Updates and revisions

The following snippet assumes the `vault` instance above and an existing bucket:

```csharp
var created = await vault.AddSecretAsync("app_prod", "Feature:Enabled", "true");

var updated = await vault.UpdateSecretAsync(
    "app_prod",
    "Feature:Enabled",
    "false",
    created.Revision
);

await vault.DeleteSecretAsync("app_prod", "Feature:Enabled", updated.Revision);
```

Updates/deletes require the revision read from the affected object. A stale
revision returns `revision_conflict`; fetch current state and decide whether to
apply your change. `SetSecretAsync` with revision 0 creates only if absent.
Deleting a nonempty bucket requires `recursive: true`. Refresh bucket metadata
after secret changes before using its revision for deletion.

## Pagination

```csharp
string? cursor = null;

do {
    var page = await vault.ListSecretsAsync("app_prod", cursor, limit: 100);

    foreach (var item in page.Items) {
        // Metadata only; never print values.
        Console.WriteLine(item.Key);
    }

    cursor = page.NextCursor;
} while (cursor is not null);
```

Limits are 1–200. Cursors are opaque; continue the same listing with the returned
cursor. Neither list method automatically reads all pages.

## Errors, cancellation, and retries

```csharp
try {
    var snapshot = await vault.ReadBucketSnapshotAsync("app_prod");
} catch (DarkVaultException error) {
    Console.Error.WriteLine(
        $"DarkVault: {error.Code}; HTTP {error.Status}; request {error.RequestId}"
    );
}
```

`DarkVaultException` exposes `Code`, `Status` (0 for local/transport failures),
and optional `RequestId`. Invalid constructor arguments can throw argument
exceptions. Cancellation/deadline expiry can throw `OperationCanceledException`.

Each operation has a 30-second deadline, including discovery and retries. Pass a
cancellation token to shorten it. Reads may retry twice after network errors or
retryable 429/5xx responses. An explicit `unknown_key` response permits one key
refresh. Uncertain writes are not automatically retried: on `outcome_unknown`,
or cancellation after a write was sent, inspect current state before retrying.

Common server errors include `unauthorized`, `forbidden`, `not_found`,
`already_exists`, `revision_conflict`, and `bucket_not_empty`.

## Custom HTTP transport

```csharp
using var http = new HttpClient(new HttpClientHandler {
    AllowAutoRedirect = false
});
using var vaultWithTransport = new DarkVaultClient("https://vault.example.com", token, http);
```

Retain normal TLS validation. For a private CA, install the CA into the trust
store used by your application. Do not use an accept-all certificate callback.
The caller owns and disposes `http`. Configure transport behavior before use.

[DarkVault and server setup](https://github.com/Bobsans/DarkVault#readme) · [API schema](https://github.com/Bobsans/DarkVault/blob/main/docs/openapi.json) · [Issues](https://github.com/Bobsans/DarkVault/issues) · [MIT license](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

## Typed configuration

Secret types are string, number, boolean, and null. String reads remain available; typed reads preserve scalar types. See [the configuration contract](https://github.com/Bobsans/DarkVault/blob/main/docs/configuration.md) for SDK methods, nested paths, JSON/YAML export, and string fallback rules.

## Connection string

Use `https://<token>@host[:port]/bucket-name` to keep connection settings in one
secret variable, for example `DARKVAULT_URL`. The scheme, token and bucket are
required. Bucket names use 1–63 lowercase letters, digits, `_` or `-`, starting
with a letter or digit. Additional paths, query strings, fragments and passwords
are rejected. Use the literal token and bucket name without percent encoding.

The SDK does not read environment variables automatically. The factory separates
the token from the HTTPS origin before making requests. Treat the entire string
as a secret. Existing constructors and explicit bucket arguments still work.
The default bucket is used for bucket/configuration reads when omitted; other
operations can use the exposed default-bucket property explicitly.

```csharp
var connection = Environment.GetEnvironmentVariable("DARKVAULT_URL")
    ?? throw new InvalidOperationException("DARKVAULT_URL is required");
using var client = DarkVaultClient.FromUrl(connection);
var secrets = await client.ReadBucketAsync();
var secret = await client.ReadSecretAsync(client.DefaultBucket!, "ApiKey");
```

## Load configuration in one call

```csharp
var settings = await DarkVaultClient.LoadConfigurationAsync(
    connection, SettingsJsonContext.Default.AppSettings);
```

Supply your source-generated `JsonTypeInfo<T>`, as for `ReadConfigurationAsync`,
to preserve Native AOT support. The helper loads one typed, nested snapshot and
disposes its client. An optional cancellation token and caller-owned
`HttpClient` are supported.
