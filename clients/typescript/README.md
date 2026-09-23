# DarkVault TypeScript SDK

[![npm](https://img.shields.io/npm/v/%40darkvault%2Fclient)](https://www.npmjs.com/package/@darkvault/client)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org/)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

Typed access to DarkVault buckets and secrets from Node.js or a browser application.
Ships ESM JavaScript and TypeScript declarations; `jose` handles JWE encryption.

## Install

```sh
npm install @darkvault/client
```

Requires Node.js 24+ or a modern browser environment with Fetch, Web Crypto,
`AbortSignal.timeout`, and `AbortSignal.any`. The package is ESM, not CommonJS.

## Quick start (Node.js)

```typescript
import { DarkVaultClient } from '@darkvault/client';

const token = process.env.DARKVAULT_TOKEN;

if (!token) {
    throw new Error('DARKVAULT_TOKEN is required');
}

const vault = new DarkVaultClient('https://vault.example.com', token, {
    timeoutMs: 10_000,
});
const settings = await vault.readBucket('app_prod');
const databaseUrl = settings['Database:Url'];
```

`readBucket` returns `Record<string, string>`; `readBucketSnapshot` also returns
the bucket ID and revision. Reuse the client; there is no `close()` or disk cache.

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

Basic bucket reads expose string values. Typed-secret and configuration APIs preserve
JSON scalar types (`string`, `number`, `boolean`, and `null`); use them when loading
application settings. Treat returned values as sensitive in-memory data; do not log
values, Authorization headers, or request bodies. TLS verification must stay enabled.
JWE uses ECDH-ES/P-256/A256GCM in addition to HTTPS; the server still sees plaintext
secrets, so this is not a zero-knowledge system.

## Constructor and cancellation

```text
new DarkVaultClient(server: string, token: string, options?: ClientOptions)
```

| Option | Default | Behavior |
| --- | --- | --- |
| `timeoutMs` | `30000` | Integer from 1 to 30000; discovery and execution share the deadline |
| `fetch` | `globalThis.fetch` | Optional trusted Fetch implementation |

All operation methods accept a final optional `AbortSignal`:

```typescript
const controller = new AbortController();
const pending = vault.readBucket('app_prod', controller.signal);

// Call controller.abort() when the caller no longer needs the result.
const settings = await pending;
```

The caller signal and timeout are combined. Cancellation after sending a mutation
does not prove the server rolled it back.

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

All results below are wrapped in `Promise<T>`; deletes return `Promise<void>`.
The final optional `signal?: AbortSignal` is omitted from the table.

| Method | Result |
| --- | --- |
| `addBucket(name, description = '')` | `Bucket` |
| `getBucket(bucket)` | `Bucket` |
| `listBuckets(cursor = null, limit = 100)` | `Page<Bucket>` |
| `readBucket(bucket)` | `Record<string, string>` |
| `readBucketSnapshot(bucket)` | `BucketSnapshot` |
| `readTypedBucket(bucket)` | `Record<string, SecretScalar>` with typed values |
| `updateBucket(bucket, description, expectedRevision)` | `Bucket` |
| `deleteBucket(bucket, expectedRevision, recursive = false)` | `void` |
| `addSecret(bucket, key, value)` | `SecretMetadata` |
| `readSecret(bucket, key)` | `Secret` |
| `readTypedSecret(bucket, key)` | `Secret` with a typed `SecretScalar` value |
| `listSecrets(bucket, cursor = null, limit = 100)` | `Page<SecretMetadata>` |
| `updateSecret(bucket, key, value, expectedRevision)` | `SecretMetadata` |
| `setSecret(bucket, key, value, expectedRevision = 0)` | `SecretMetadata` |
| `deleteSecret(bucket, key, expectedRevision)` | `void` |
| `getTokenInfo()` | `TokenInfo` |
| `execute<T = unknown>(operation, parameters)` | `T`; advanced wire API |

Names, keys, and descriptions are strings. Secret writes accept `SecretScalar`
(string, number, boolean, null); ordinary reads expose canonical strings and type metadata.
Revisions must be nonnegative
safe integers; cursors are `string | null`. Limits are integers from 1 to 200.

Exported interfaces:

- `Bucket`: `id`, `name`, `description`, `revision`, `createdAt`, `updatedAt`.
- `SecretMetadata`: `id`, `bucketId`, `key`, `revision`, `createdAt`, `updatedAt`, `type`.
- `Secret`: extends metadata with `value`.
- `BucketSnapshot`: `bucketId`, `revision`, `secrets`, sparse `types`.
- `Page<T>`: `items: T[]`, `nextCursor: string | null`.
- `TokenInfo`: `id`, `name`, `scopes`, `bucketIds`, `allBuckets`,
  `creatableBucketNames`, `expiresAt`.
- `ClientOptions`: `timeoutMs?`, `fetch?`.

Dates are ISO 8601 strings; token expiry may be null. `execute<T>` provides a
compile-time result type, not runtime validation of an arbitrary schema.

## Create, update, and delete

With the `vault` instance above and an existing bucket:

```typescript
const created = await vault.addSecret('app_prod', 'Feature:Enabled', 'true');

const updated = await vault.updateSecret(
    'app_prod',
    'Feature:Enabled',
    'false',
    created.revision,
);

await vault.deleteSecret('app_prod', 'Feature:Enabled', updated.revision);
```

Updates and deletes require the affected object's current revision. A stale one
returns `revision_conflict`. Read current state before deciding whether to retry.
`setSecret` with revision 0 creates only if absent, not unconditional overwrite.
Deleting a nonempty bucket requires `recursive = true`; refresh its metadata
after secret changes before using the bucket revision for deletion.

## Pagination

```typescript
let cursor: string | null = null;

do {
    const page = await vault.listSecrets('app_prod', cursor, 100);

    for (const item of page.items) {
        // Metadata only; no secret values.
        console.log(item.key);
    }

    cursor = page.nextCursor;
} while (cursor !== null);
```

Each list call returns one page. Treat cursors as opaque and keep them with the
same listing. Secret listings do not include values.

## Errors and retries

```typescript
import { DarkVaultError } from '@darkvault/client';

try {
    await vault.readBucket('app_prod');
} catch (error) {
    if (error instanceof DarkVaultError) {
        console.error(error.code, error.status, error.requestId);
    } else {
        // Includes cancellation and other runtime errors.
        throw error;
    }
}
```

`DarkVaultError` exposes safe `code`, `status`, and `requestId` fields.
Constructor validation and invalid revisions/limits may throw `TypeError`.
Abort/timeout and some parsing or crypto failures may be other exception types.

No requests are automatically retried. `request_outcome_unknown` means a request
to the execute endpoint failed in transit; after a mutation, read current state
before retrying. Common server codes include `unauthorized`, `forbidden`,
`not_found`, `already_exists`, `revision_conflict`, and `bucket_not_empty`.

## TLS, custom Fetch, and browsers

TLS trust is provided by the runtime. For a private CA in Node.js, set
`NODE_EXTRA_CA_CERTS` to a trusted CA PEM file **before starting Node**.
Do not disable certificate validation. Requests reject redirects, omit cookies,
and use `cache: 'no-store'`. A supplied Fetch implementation receives the token,
so treat it as trusted application code.

Browser use requires a same-origin deployment or explicitly configured trusted
CORS policy. The server does not enable cross-origin access by default.
Never bundle a permanent privileged token into frontend assets. The SDK does not
manage browser login, persist tokens, or use the admin UI's session cookies.

The `@darkvault/client/protocol` subpath exposes the shared low-level JWE helpers
used by the administrative UI. Most applications should use `DarkVaultClient`;
the protocol helpers do not replace token authorization or CSRF/session handling.

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

```typescript
const connection = process.env.DARKVAULT_URL;
if (!connection) throw new Error('DARKVAULT_URL is required');
const vault = DarkVaultClient.fromUrl(connection);
const secrets = await vault.readBucket();
const config = await vault.readConfiguration();
const secret = await vault.readSecret(vault.defaultBucket!, 'ApiKey');
```

The second factory argument accepts the existing `ClientOptions`.

## Load configuration in one call

```typescript
import { loadConfiguration } from '@darkvault/client';

const settings = await loadConfiguration(connection);
```

Returns a typed nested configuration snapshot. The optional second argument
accepts `ClientOptions`; the third accepts an `AbortSignal`. Errors propagate to
the caller. For flat keys or repeated requests, use the client API.

## Rename a bucket

`renameBucket(bucket, name, expectedRevision)` renames a bucket with `bucket:write` and its current revision. Its ID, secrets, description, and token access are preserved. Update the bucket name in application configuration after renaming.

## Load settings from the environment

```typescript
const settings = await loadConfiguration();
```

In Node.js, an omitted URL reads `process.env.DARKVAULT_URL`. Pass `undefined`
to use the environment together with options or an `AbortSignal`.
An explicitly empty URL is rejected. In browsers, pass a URL explicitly.

Missing or whitespace-only `DARKVAULT_URL` produces a clear error. An explicit
URL is used independently of the environment. The SDK does not load `.env` files;
load one beforehand if needed. Existing timeouts and cancellation behavior apply.
