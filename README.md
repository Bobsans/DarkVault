# DarkVault

**Your secrets. Your server. One API for every application.**

[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/Bobsans/DarkVault)](https://github.com/Bobsans/DarkVault/releases/latest)
[![NuGet](https://img.shields.io/nuget/v/DarkVault.Client)](https://www.nuget.org/packages/DarkVault.Client)
[![PyPI](https://img.shields.io/pypi/v/darkvault-client)](https://pypi.org/project/darkvault-client/)
[![npm](https://img.shields.io/npm/v/%40darkvault%2Fclient)](https://www.npmjs.com/package/@darkvault/client)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

DarkVault is a self-hosted secrets manager for applications, scripts, and services.
Organize credentials into buckets, give each application scoped access, and load
its configuration through a native SDK or a single CLI command.

**Start with one bucket. Connect your first app. Keep control of where its secrets live.**

## Why try DarkVault?

- **A small deployment footprint.** One ASP.NET Core service and SQLite, with a web interface included.
- **Use the language you already use.** C#, Python, Go, TypeScript, and a standalone CLI.
- **Application-friendly configuration.** Read a whole bucket, load .NET configuration, or inject a child process's environment.
- **Scoped credentials.** Limit tokens by operation and bucket, set expiration, and revoke access.
- **Encryption in transit and at rest.** HTTPS plus JWE request/response encryption; AES-GCM for stored secret values.
- **Explicit concurrency.** Revision checks prevent silent overwrites of another writer's changes.
- **Operational tools included.** Backups, integrity verification, key rotation, and auditing.

## Choose your client

| Client                   | Install                                                 | User guide                                                                            |
|--------------------------|---------------------------------------------------------|---------------------------------------------------------------------------------------|
| C# / .NET 10             | `dotnet add package DarkVault.Client`                   | [C# SDK](clients/csharp/DarkVault.Client/README.md)                                   |
| .NET configuration       | `dotnet add package DarkVault.Extensions.Configuration` | [Configuration provider](clients/csharp/DarkVault.Extensions.Configuration/README.md) |
| Python 3.11+             | `python -m pip install darkvault-client`                | [Python SDK](clients/python/README.md)                                                |
| Go 1.25+                 | `go get github.com/Bobsans/DarkVault/clients/go@latest` | [Go SDK](clients/go/README.md)                                                        |
| TypeScript / Node.js 22+ | `npm install @darkvault/client`                         | [TypeScript SDK](clients/typescript/README.md)                                        |
| Command line             | Download the CLI for your OS                            | [CLI guide](cli/README.md)                                                            |

See [GitHub Releases](https://github.com/Bobsans/DarkVault/releases) for binaries and
package archives. Registry badges reflect each registry independently; packages
become installable after their first publication.

## Get started

### 1. Run your vault

Download and extract the **server** archive for your OS and architecture from
[Releases](https://github.com/Bobsans/DarkVault/releases). Server releases use
Native AOT for Windows, Linux, and macOS (x64/ARM64); no .NET installation is needed.
Keep the executable, SQLite library, and `wwwroot` files together.

From the extracted directory, on Linux or macOS:

```sh
export DARKVAULT_DATA="$HOME/.darkvault-data"
./DarkVault.Server bootstrap
./DarkVault.Server serve
```

On Windows, in PowerShell:

```powershell
$env:DARKVAULT_DATA = 'D:/DarkVaultData'
./DarkVault.Server.exe bootstrap
./DarkVault.Server.exe serve
```

Use a dedicated, empty data directory owned by the service account. DarkVault
restricts its permissions. `bootstrap` prompts privately for an administrator
password of at least 15 characters; the login is `admin`.

### 2. Put HTTPS in front

The default backend listens on `127.0.0.1:8866`. Run a trusted HTTPS reverse proxy
on the same host; do not expose the plaintext backend to the internet.
For example, with Caddy and a domain pointing to your server:

```caddyfile
vault.example.com {
    reverse_proxy 127.0.0.1:8866
}
```

Allow ports 80 and 443 for the public domain. A [Caddy template](deploy/Caddyfile)
and [systemd service template](deploy/darkvault.service) are included.
`/health/ready` provides a readiness check.

### 3. Create a bucket and token

Open `https://vault.example.com`, sign in as `admin`, create a bucket such as
`app_prod`, and add secrets. Issue an application token with access to that bucket.
Reading the complete bucket requires `bucket:read`, `secret:read`, and `secret:list`.

Store that token in your deployment's protected secret source. Examples below read
`DARKVAULT_TOKEN` explicitly; SDKs do not load environment variables automatically.

### 4. Connect your application

**Python**

```python
import os

from darkvault import DarkVaultClient

with DarkVaultClient(
    "https://vault.example.com",
    os.environ["DARKVAULT_TOKEN"],
) as vault:
    settings = vault.read_bucket("app_prod")
    database_url = settings["Database:Url"]
```

**TypeScript**

```typescript
import { DarkVaultClient } from '@darkvault/client';

const token = process.env.DARKVAULT_TOKEN;

if (!token) {
    throw new Error('DARKVAULT_TOKEN is required');
}

const vault = new DarkVaultClient('https://vault.example.com', token);
const settings = await vault.readBucket('app_prod');
```

**ASP.NET Core configuration**

```csharp
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);
var token = Environment.GetEnvironmentVariable("DARKVAULT_TOKEN")
    ?? throw new InvalidOperationException("DARKVAULT_TOKEN is required");

await builder.Configuration.AddFromDarkVaultBucketAsync(
    "https://vault.example.com",
    token,
    "app_prod"
);

var app = builder.Build();
app.Run();
```

**CLI — no application code required**

```sh
darkvault config set server https://vault.example.com
darkvault config set token
darkvault exec \
    --bucket app_prod \
    --aspnet-keys \
    -- dotnet MyApp.dll
```

The token prompt is hidden. `exec` loads secrets into the child process's environment;
`--aspnet-keys` maps `:` to `__` for .NET configuration.

## Security and operations

DarkVault is a server-side vault: the server decrypts secrets in memory, and the
HTTPS proxy is trusted. It is **not a zero-knowledge system**. Protect the server,
data directory, backups, and application tokens. Keep TLS validation enabled and
avoid logging secret values, request bodies, or Authorization headers.

Run one server process per data directory. To back up, stop the service and run
`DarkVault.Server backup <new-directory>` using the same data directory and account
(use `./DarkVault.Server` on Unix or `./DarkVault.Server.exe` on Windows).
Both `vault.db` and `keyring.json` are required to restore. After restoring, run
`verify`, then **`rotate-data` before the first write**, review token revocations
made since the backup, and restart the service.

## Documentation

- Client guides: [C#](clients/csharp/DarkVault.Client/README.md), [configuration](clients/csharp/DarkVault.Extensions.Configuration/README.md), [Python](clients/python/README.md), [Go](clients/go/README.md), [TypeScript](clients/typescript/README.md), [CLI](cli/README.md).
- [HTTP API schema](docs/openapi.json) and [ASP.NET sample](samples/AspNet).
- Maintainer reference (currently in Russian): [operations](docs/operations.md), [protocol](docs/protocol.md), [verification](docs/verification.md), [versioning](docs/versioning.md), [publishing](docs/publishing.md).

## Build from source

With the .NET 10 SDK, run from the repository root:

```sh
dotnet publish server/DarkVault.Server/DarkVault.Server.csproj \
    -c Release \
    -o artifacts/server
```

The browser bundle is included; changing frontend sources additionally requires
Node.js 22+ and pnpm 11. Contributor checks run with `pwsh tools/verify.ps1`.

## Give it a try

Move one application's configuration into a bucket and see how it fits your workflow.
Found a rough edge or have an integration idea? [Open an issue](https://github.com/Bobsans/DarkVault/issues).
If DarkVault helps you, **star the repository** so other developers can discover it.

Released under the [MIT license](LICENSE).
