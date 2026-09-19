# DarkVault Python client

Synchronous Python 3.11+ SDK for the DarkVault HTTP/JWE API. All data operations are
available; administrative login and token issuance belong to the server's web UI.

## Install from this repository

```sh
python -m pip install ./clients/python
```

The package is not published to PyPI. Its only direct runtime dependency is
[jwcrypto](https://jwcrypto.readthedocs.io/en/latest/jwe.html), which implements
standard JWE. HTTPS uses Python's standard library and the system trust store.

## Read a bucket

```python
import os
from darkvault import DarkVaultClient

with DarkVaultClient("https://vault.example.com", os.environ["DARKVAULT_TOKEN"]) as vault:
    secrets = vault.read_bucket("app_qa")
    database_url = secrets["ConnectionStrings:Main"]
```

`read_bucket` returns `dict[str, str]`, preserving case, Unicode, empty strings and
newlines. `read_bucket_snapshot` also returns `bucketId` and `revision`. No partial
dictionary is returned if decryption or validation fails. The SDK does not read or
modify the Go CLI's config, global environment, or a disk cache.

## Write and update

```python
with DarkVaultClient(server, token, timeout=10) as vault:
    bucket = vault.add_bucket("app_qa", description="QA settings")
    secret = vault.add_secret("app_qa", "Feature:Enabled", "true")
    updated = vault.update_secret(
        "app_qa", "Feature:Enabled", "false", expected_revision=secret["revision"]
    )
    vault.delete_secret("app_qa", "Feature:Enabled", updated["revision"])
    current = vault.get_bucket("app_qa")
    vault.delete_bucket("app_qa", current["revision"])
```

Methods and results:

| Method | Result |
| --- | --- |
| `add_bucket(name, description="")` | Bucket metadata |
| `get_bucket(bucket)` | Bucket metadata |
| `list_buckets(cursor=None, limit=100)` | Page: `items`, `nextCursor` |
| `read_bucket(bucket)` | Secret dictionary |
| `read_bucket_snapshot(bucket)` | `bucketId`, `revision`, `secrets` |
| `update_bucket(bucket, description, expected_revision)` | Updated metadata |
| `delete_bucket(bucket, expected_revision, recursive=False)` | `None` |
| `add_secret(bucket, key, value)` | Secret metadata |
| `read_secret(bucket, key)` | Metadata plus `value` |
| `list_secrets(bucket, cursor=None, limit=100)` | Metadata page, without values |
| `update_secret(bucket, key, value, expected_revision)` | Updated metadata |
| `set_secret(bucket, key, value, expected_revision=0)` | Metadata; 0 means create if absent |
| `delete_secret(bucket, key, expected_revision)` | `None` |
| `get_token_info()` | Own scopes, grants and expiry |

Metadata dictionaries use the wire contract's camelCase field names. Dates remain
UTC RFC 3339 strings. List options (`cursor`, `limit`) and `recursive` are keyword-only.
Use `nextCursor` for the next page; `None` means there are no more pages.
Revisions come from reads. The SDK does not silently fetch a newer revision and
overwrite a concurrent change. Deleting a nonempty bucket requires `recursive=True`.

## Errors and lifetime

```python
from darkvault import DarkVaultError

try:
    secrets = vault.read_bucket("app_qa")
except DarkVaultError as error:
    print(error.code, error.status, error.request_id)
```

Errors contain safe codes, HTTP status (0 for a local/transport error) and the local
request ID when available, never raw payloads or credentials. For a mutation with
`outcome_unknown`, inspect the server state before retrying. Network failures and
plaintext 429/5xx responses for reads have at most two retries; `Retry-After` is
honored within the remaining time budget. An explicit `unknown_key` response permits
one key refresh because the server has not executed that command.

Reuse a client and close it, preferably with `with`. Calls share one HTTPS connection
and serialize; use one client per worker for parallel I/O. Timeout defaults to 30
seconds and can be reduced; the deadline covers discovery, retries and the command.
OS-level hostname resolution remains subject to the platform resolver's behavior.

Certificate and hostname verification are mandatory. Redirects, URL credentials,
HTTP downgrade, compression and unencrypted success responses are rejected. For a
private CA, pass a verifying `ssl.SSLContext` with `load_verify_locations(...)`;
disabling certificate/hostname checks is rejected. The client connects directly,
without automatically inheriting proxy or credential environment variables.

The server sees plaintext secrets in memory. JWE uses `ECDH-ES`, P-256 and `A256GCM`,
the same profile as the C# SDK, Go CLI and browser. This is not a zero-knowledge vault.

## Tests and package

```sh
python -m pip install -e ./clients/python build
python -m unittest discover -s clients/python/tests -v
python -m build clients/python --outdir artifacts/python
```

The shared fixture contains only public test keys. Live tests run when
`DARKVAULT_ACCEPTANCE` points to the temporary local server descriptor; the repository's
`tools/verify.ps1` starts the server, runs these tests and cleans up its private state.
