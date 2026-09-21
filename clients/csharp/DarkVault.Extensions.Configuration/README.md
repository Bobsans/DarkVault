# DarkVault.Extensions.Configuration

[![NuGet](https://img.shields.io/nuget/v/DarkVault.Extensions.Configuration)](https://www.nuget.org/packages/DarkVault.Extensions.Configuration)
[![.NET 10](https://img.shields.io/badge/runtime-.NET%2010-blue)](https://github.com/Bobsans/DarkVault)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

Load a DarkVault bucket into standard .NET configuration before your application starts.
Works with `IConfiguration`, ASP.NET Core, and the options pattern.

## Install

```sh
dotnet add package DarkVault.Extensions.Configuration
```

Targets .NET 10 and includes the DarkVault client dependency.

## ASP.NET Core quick start

Create a bucket named `app_prod` containing a key such as `ConnectionStrings:Main`.
Issue a token with `bucket:read`, `secret:read`, `secret:list`, and access to that bucket.

```csharp
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var token = Environment.GetEnvironmentVariable("DARKVAULT_TOKEN")
    ?? throw new InvalidOperationException("DARKVAULT_TOKEN is required");

using var startupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

await builder.Configuration.AddFromDarkVaultBucketAsync(
    "https://vault.example.com",
    token,
    "app_prod",
    startupTimeout.Token
);

// Providers added later override values loaded from DarkVault.
builder.Configuration.AddEnvironmentVariables();
var connectionString = builder.Configuration.GetConnectionString("Main");

var app = builder.Build();
app.Run();
```

The token is read explicitly by this example. The extension does not read CLI
configuration or discover credentials. Use an HTTPS origin, not an API path.
Keep the token in your deployment's protected secret source.

## Available overloads

Namespace: `Microsoft.Extensions.Configuration`. Both methods extend
`IConfigurationBuilder` and return `Task<IConfigurationBuilder>`.

```text
AddFromDarkVaultBucketAsync(
    string server,
    string token,
    string bucket,
    CancellationToken cancellationToken = default
)

AddFromDarkVaultBucketAsync(
    DarkVaultClient client,
    string bucket,
    CancellationToken cancellationToken = default
)
```

The server/token overload creates and disposes a client internally. The client
overload leaves ownership with the caller, allowing reuse or custom transport:

```csharp
using DarkVault.Client;
using Microsoft.Extensions.Configuration;

using var http = new HttpClient(new HttpClientHandler {
    AllowAutoRedirect = false
});
using var vault = new DarkVaultClient("https://vault.example.com", token, http);

var configurationBuilder = new ConfigurationBuilder();

await configurationBuilder.AddFromDarkVaultBucketAsync(vault, "app_prod");

var configuration = configurationBuilder.Build();
```

This snippet uses the `token` loaded in the quick start. Preserve TLS certificate
validation; trust your private CA through the application's normal trust store.

## Keys and precedence

Keys are added unchanged. `ConnectionStrings:Main` is a hierarchical .NET key;
`Feature:Enabled` can be read with `configuration["Feature:Enabled"]`.
No `:` to `__` conversion occurs here; that mapping belongs to environment variables.

Standard configuration precedence applies: **later providers win**. Appending
DarkVault after `WebApplication.CreateBuilder` overrides its earlier providers,
including existing environment/command-line values. Add those providers again
after DarkVault only when they should take precedence.

.NET configuration compares keys without case. A bucket containing both
`ApiKey` and `apikey` is rejected with `InvalidOperationException`, rather than
choosing a value silently.

## Loading, failures, and lifecycle

- The entire bucket is fetched and checked before adding the in-memory provider.
- A failed request or case-insensitive key collision adds no provider.
- Loading happens once. There is no background polling, automatic reload, or disk cache.
- Failures propagate to the caller. An unhandled startup failure stops startup.
- Configuration values remain in application memory after the client is disposed.
- Restart or explicitly reload your application configuration to pick up secret changes.
- Cancellation is supported; the underlying client has a 30-second operation deadline.

Handle `DarkVaultException` using its safe `Code`, `Status`, and `RequestId`
fields, and `OperationCanceledException` for cancellation. Do not silently fall
back to stale/default credentials unless that is an intentional application policy.

A `forbidden` response usually calls for checking all three read scopes and the
bucket grant. A missing bucket requires correcting its exact name. The server
decrypts secrets in memory; this is not a zero-knowledge store.

## More examples

[Full C# client API](https://github.com/Bobsans/DarkVault/blob/main/clients/csharp/DarkVault.Client/README.md) ·
[ASP.NET sample](https://github.com/Bobsans/DarkVault/tree/main/samples/AspNet)

[DarkVault and server setup](https://github.com/Bobsans/DarkVault#readme) · [API schema](https://github.com/Bobsans/DarkVault/blob/main/docs/openapi.json) · [Issues](https://github.com/Bobsans/DarkVault/issues) · [MIT license](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

## Typed configuration

Secret types are string, number, boolean, and null. String reads remain available; typed reads preserve scalar types. See [the configuration contract](https://github.com/Bobsans/DarkVault/blob/main/docs/configuration.md) for SDK methods, nested paths, JSON/YAML export, and string fallback rules.

## Connection string

```csharp
var connection = Environment.GetEnvironmentVariable("DARKVAULT_URL")
    ?? throw new InvalidOperationException("DARKVAULT_URL is required");
builder.Configuration.AddFromDarkVault(connection);
```

The format is `https://<token>@host[:port]/bucket-name`. The bucket is read once,
using the existing configuration provider behavior. The entire string is a
secret; the provider never uses its token as part of the HTTP request URL.

`AddFromDarkVault(url)` loads once and blocks until the configuration is ready,
so use it during application startup. It returns the builder for chaining.
For asynchronous startup, use:

```csharp
await builder.Configuration.AddFromDarkVaultAsync(connection);
```

Both methods accept an optional `CancellationToken` and caller-owned `HttpClient`
(`httpClient: http`). Loading errors are propagated; a failed load adds no
configuration source. Values override earlier providers; later providers can
override DarkVault. Existing case-insensitive key collision checks and typed-null
handling apply. There is no automatic refresh.

The previous `AddFromDarkVaultBucketAsync` overloads remain available.
