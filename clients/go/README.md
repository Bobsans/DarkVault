# DarkVault Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/Bobsans/DarkVault/clients/go/v2.svg)](https://pkg.go.dev/github.com/Bobsans/DarkVault/clients/go/v2)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8)](https://go.dev/)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

A standalone Go client with typed bucket, secret, and token operations.
The module is independent of the CLI, Cobra, and the DarkVault server project.

## Install

Requires Go 1.25+:

```sh
go get github.com/Bobsans/DarkVault/clients/go/v2@latest
```

Pin a published version for reproducible builds. Releases use module tags such as
`clients/go/v2.0.0`; consumers request `@v2.0.0`.

## Quick start

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	darkvault "github.com/Bobsans/DarkVault/clients/go/v2"
)

func main() {
	vault, err := darkvault.New("https://vault.example.com", os.Getenv("DARKVAULT_TOKEN"))
	if err != nil {
		log.Fatal("Invalid DarkVault configuration")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	settings, err := vault.ReadBucket(ctx, "app_prod")
	if err != nil {
		log.Fatal("Cannot load DarkVault settings")
	}

	// Pass to your application; do not log secrets.
	_ = settings["Database:Url"]
}
```

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

All methods below take `ctx context.Context` as their first argument. They return
`(Result, error)`; delete methods return only `error`.

| Method (excluding context) | Result |
| --- | --- |
| `AddBucket(name, description)` | `Bucket` |
| `GetBucket(bucket)` | `Bucket` |
| `ListBuckets(cursor, limit)` | `Page[Bucket]` |
| `ReadBucket(bucket)` | `map[string]string` |
| `ReadBucketSnapshot(bucket)` | `BucketSnapshot` |
| `UpdateBucket(bucket, description, expectedRevision)` | `Bucket` |
| `DeleteBucket(bucket, expectedRevision, recursive)` | Error only |
| `AddSecret(bucket, key, value)` | `SecretMetadata` |
| `ReadSecret(bucket, key)` | `Secret` |
| `ListSecrets(bucket, cursor, limit)` | `Page[SecretMetadata]` |
| `UpdateSecret(bucket, key, value, expectedRevision)` | `SecretMetadata` |
| `SetSecret(bucket, key, value, expectedRevision)` | `SecretMetadata` |
| `DeleteSecret(bucket, key, expectedRevision)` | Error only |
| `GetTokenInfo()` | `TokenInfo` |
| `Execute(operation, parameters)` | `json.RawMessage`; advanced wire API |

Names, keys, values, descriptions, and cursors are strings; revisions are `int64`,
limits are `int`, and `recursive` is `bool`. Go has no optional method arguments:
pass `""`, `100`, `0`, or `false` explicitly where appropriate.

- `Bucket`: `ID`, `Name`, `Description`, `Revision`, `CreatedAt`, `UpdatedAt`.
- `SecretMetadata`: `ID`, `BucketID`, `Key`, `Revision`, `CreatedAt`, `UpdatedAt`, `Type`.
- `Secret`: embedded `SecretMetadata` plus `Value`.
- `BucketSnapshot`: `BucketID`, `Revision`, `Secrets`, sparse `Types`
  (a missing key means `string`).
- `Page[T]`: `Items []T`, `NextCursor *string`.
- `TokenInfo`: `ID`, `Name`, `Scopes`, `BucketIDs`, `AllBuckets`,
  `CreatableBucketNames`, `ExpiresAt`.

Timestamps use `time.Time`; token expiry is `*time.Time` and may be nil.
Secret listings contain metadata, not values.

## Update a secret

Inside a function with the `vault` and `ctx` from above that returns `error`:

```go
current, err := vault.ReadSecret(ctx, "app_prod", "Feature:Enabled")
if err != nil {
	return err
}

_, err = vault.UpdateSecret(
	ctx,
	"app_prod",
	"Feature:Enabled",
	"false",
	current.Revision,
)

return err
```

Stale revisions fail with `revision_conflict`. `SetSecret` with revision 0 creates
only if absent; it is not an unconditional overwrite. Delete operations require a
current revision; nonempty buckets additionally require `recursive = true`.
Refresh bucket metadata after changing secrets before deleting the bucket.

## Pagination

Inside a function returning `error`:

```go
cursor := ""

for {
	page, err := vault.ListSecrets(ctx, "app_prod", cursor, 100)
	if err != nil {
		return err
	}

	for _, item := range page.Items {
		// Process metadata.
		_ = item.Key
	}

	if page.NextCursor == nil {
		break
	}

	cursor = *page.NextCursor
}

return nil
```

Use an empty cursor initially and a limit from 1 to 200. Cursors are opaque and
belong to the same listing. Each call returns one page.

## Errors, deadlines, and retries

Use `errors.As` to inspect server error metadata:

```go
var apiError *darkvault.APIError

if errors.As(err, &apiError) {
	log.Printf(
		"DarkVault: %s; HTTP %d; request %s",
		apiError.Code,
		apiError.Status,
		apiError.RequestID,
	)
}
```

Import `errors` and use the returned `err`. Not all failures are `APIError`:
configuration, transport, context, and decoding errors can be ordinary Go errors.
Common server codes include `unauthorized`, `forbidden`, `not_found`,
`already_exists`, `revision_conflict`, and `bucket_not_empty`.

Discovery and execution share a deadline of at most 30 seconds, shortened by
`Client.HTTP.Timeout` or the caller's context. No requests are retried automatically.
A write interrupted by a network error or cancellation may already have succeeded;
read current state before retrying.

## HTTP transport and private CAs

`New(server, token)` returns `(*Client, error)` and configures a 30-second
`http.Client`. Reuse it. Set `Client.HTTP` before requests if a custom transport
is needed; do not mutate client fields while requests are running.
The SDK rejects redirects even when a custom HTTP client is supplied.

For a private CA, configure a verifying `http.Transport` with your certificate
pool in `TLSClientConfig.RootCAs`, preserving existing system roots if needed.
Never set `InsecureSkipVerify`. Use Go's normal transport lifecycle for connection
cleanup; the SDK has no `Close` method.

## Local checkout

Before a module version is published, a consuming Go module can use a local
`replace github.com/Bobsans/DarkVault/clients/go/v2 => /path/to/DarkVault/clients/go`.
Published module versions do not need that replacement.

[DarkVault and server setup](https://github.com/Bobsans/DarkVault#readme) · [API schema](https://github.com/Bobsans/DarkVault/blob/main/docs/openapi.json) · [Issues](https://github.com/Bobsans/DarkVault/issues) · [MIT license](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

## Typed configuration

Secret types are string, number, boolean, and null. String reads remain available; typed reads preserve scalar types. See [the configuration contract](https://github.com/Bobsans/DarkVault/blob/main/docs/configuration.md) for SDK methods, nested paths, JSON/YAML export, and string fallback rules.

## Connection string

Use `https://<token>@host[:port]/bucket-name` to keep connection settings in one
secret variable, for example `DARKVAULT_URL`. The scheme, token and bucket are
required. Bucket names use 1–63 lowercase letters, digits, `_` or `-`, starting
with a letter or digit. Additional paths, query strings, fragments and passwords
are rejected. Use the literal token and bucket name without percent encoding.

The client constructor and URL factory do not read environment variables. The factory separates
the token from the HTTPS origin before making requests. Treat the entire string
as a secret. Existing constructors and explicit bucket arguments still work.
The default bucket is used for bucket/configuration reads when omitted; other
operations can use the exposed default-bucket property explicitly.

```go
vault, err := darkvault.NewFromURL(os.Getenv("DARKVAULT_URL"))
if err != nil {
    return err
}
secrets, err := vault.ReadBucket(ctx, "")
```

In Go, pass an empty bucket for `ReadBucket`, `ReadBucketSnapshot`,
`ReadTypedBucket` and `ReadConfiguration` to use `DefaultBucket`. For other
operations, pass `vault.DefaultBucket` explicitly.

## Load configuration in one call

```go
if err := darkvault.LoadConfiguration(ctx, os.Getenv("DARKVAULT_URL"), &settings); err != nil {
    return err
}
```

Pass a pointer to a struct or map. The helper uses the existing typed, nested
configuration binding and returns any connection, validation or decoding error.
Cancellation comes from `ctx`. It uses the standard HTTP transport and system
trust store; create a client explicitly for a custom transport.

## Rename a bucket

`RenameBucket(ctx, bucket, name, expectedRevision)` renames a bucket with `bucket:write` and its current revision. Its ID, secrets, description, and token access are preserved. Update the bucket name in application configuration after renaming.

## Load settings from the environment

```go
err := darkvault.LoadConfigurationFromEnv(ctx, &settings)
```

Go has no overloads, so a separate helper reads `DARKVAULT_URL` and delegates to
`LoadConfiguration`.

Missing or whitespace-only `DARKVAULT_URL` produces a clear error. An explicit
URL is used independently of the environment. The SDK does not load `.env` files;
load one beforehand if needed. Existing timeouts and cancellation behavior apply.
