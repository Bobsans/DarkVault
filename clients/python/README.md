# DarkVault Python SDK

[![PyPI](https://img.shields.io/pypi/v/darkvault-client)](https://pypi.org/project/darkvault-client/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/darkvault-client/)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

A synchronous Python client for DarkVault. Read configuration buckets, manage
individual secrets, and use optimistic concurrency without implementing JWE yourself.

## Install

```sh
python -m pip install darkvault-client
```

Requires Python 3.11+. The package name is `darkvault-client`; the import is
`darkvault`. The direct runtime dependency is `jwcrypto`.

## Quick start

```python
import os

from darkvault import DarkVaultClient

with DarkVaultClient(
    "https://vault.example.com",
    os.environ["DARKVAULT_TOKEN"],
    timeout=10,
) as vault:
    settings = vault.read_bucket("app_prod")
    database_url = settings["Database:Url"]
```

The result is a `dict[str, str]`. Case, Unicode, empty strings, and newlines are
preserved. `read_bucket_snapshot` additionally returns the bucket ID and revision.

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

## Constructor and lifetime

```text
DarkVaultClient(server, token, *, timeout=30, ssl_context=None)
```

`timeout` is a finite number of seconds greater than 0 and at most 30. It covers
discovery, retries, and the command together. OS hostname resolution is subject to
the platform resolver's behavior.

Reuse a client, preferably with `with`; alternatively call `close()` when finished.
Calls on one client serialize over a shared HTTPS connection. Use one client per
worker for parallel I/O. This SDK is synchronous, not an asyncio client.
Invalid constructor settings raise `ValueError`; a closed client cannot be reused.

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

| Method | Result |
| --- | --- |
| `add_bucket(name, description="")` | Bucket metadata |
| `get_bucket(bucket)` | Bucket metadata |
| `list_buckets(*, cursor=None, limit=100)` | Page |
| `read_bucket(bucket)` | `dict[str, str]` |
| `read_bucket_snapshot(bucket)` | `bucketId`, `revision`, `secrets` |
| `update_bucket(bucket, description, expected_revision)` | Bucket metadata |
| `delete_bucket(bucket, expected_revision, *, recursive=False)` | `None` |
| `add_secret(bucket, key, value)` | Secret metadata |
| `read_secret(bucket, key)` | Secret metadata plus `value` |
| `list_secrets(bucket, *, cursor=None, limit=100)` | Page of metadata without values |
| `update_secret(bucket, key, value, expected_revision)` | Secret metadata |
| `set_secret(bucket, key, value, expected_revision=0)` | Secret metadata |
| `delete_secret(bucket, key, expected_revision)` | `None` |
| `get_token_info()` | Token metadata |
| `execute(operation, parameters)` | Validated dictionary for a supported data operation; advanced wire API |

Names, keys, descriptions, and values are strings. Revisions are integers from 0
through 9007199254740991. List options and `recursive` are keyword-only.

Metadata is returned as dictionaries with camelCase keys:

- Bucket: `id`, `name`, `description`, `revision`, `createdAt`, `updatedAt`.
- Secret metadata: `id`, `bucketId`, `key`, `revision`, `createdAt`, `updatedAt`.
- Page: `items`, `nextCursor`.
- Token: `id`, `name`, `scopes`, `bucketIds`, `allBuckets`,
  `creatableBucketNames`, `expiresAt`.

Dates are UTC RFC 3339 strings; `expiresAt` may be `None`.

## Create, update, and delete

Inside a `with DarkVaultClient(...) as vault:` block, with an existing bucket:

```python
created = vault.add_secret("app_prod", "Feature:Enabled", "true")

updated = vault.update_secret(
    "app_prod",
    "Feature:Enabled",
    "false",
    expected_revision=created["revision"],
)

vault.delete_secret("app_prod", "Feature:Enabled", updated["revision"])
```

A stale revision returns `revision_conflict`. Read current state before deciding
whether to retry. `set_secret` with revision 0 creates only when absent.
Deleting a nonempty bucket needs `recursive=True`; fetch fresh bucket metadata
after changing secrets before deleting the bucket.

## Pagination

Inside the same client context:

```python
cursor = None

while True:
    page = vault.list_secrets("app_prod", cursor=cursor, limit=100)

    for item in page["items"]:
        # Metadata only.
        print(item["key"])

    cursor = page["nextCursor"]

    if cursor is None:
        break
```

Limits are 1–200. Treat cursors as opaque and use them for the same listing.
The SDK returns one page per call.

## Errors and retries

```python
from darkvault import DarkVaultError

try:
    settings = vault.read_bucket("app_prod")
except DarkVaultError as error:
    print(error.code, error.status, error.request_id)
```

Run this inside the live client context. `DarkVaultError` carries safe metadata,
not credentials or raw payloads. Status is 0 for a local/transport failure.
Server errors include `unauthorized`, `forbidden`, `not_found`,
`already_exists`, `revision_conflict`, and `bucket_not_empty`.

Reads may retry twice on network failures and plaintext 429/5xx responses.
`Retry-After` is honored within the deadline. An explicit `unknown_key` response
permits one key refresh. Uncertain writes are not retried: on `outcome_unknown`,
read the server state before repeating the mutation.

## Private certificates and networking

```python
import ssl

context = ssl.create_default_context()
context.load_verify_locations(cafile="/path/to/company-ca.pem")

with DarkVaultClient(
    "https://vault.example.com",
    token,
    ssl_context=context,
) as vault:
    settings = vault.read_bucket("app_prod")
```

Here `token` is the token loaded from your protected source. The CA file contains
public trust certificates, not your client token. Disabling certificate or hostname
verification is rejected. Redirects and plaintext success responses are rejected.
The client connects directly and does not inherit proxy/credential environment settings.

## Local installation

From a source checkout: `python -m pip install ./clients/python`.
For consumer applications, use a published PyPI version and pin it through your
normal dependency management.

[DarkVault and server setup](https://github.com/Bobsans/DarkVault#readme) · [API schema](https://github.com/Bobsans/DarkVault/blob/main/docs/openapi.json) · [Issues](https://github.com/Bobsans/DarkVault/issues) · [MIT license](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)
