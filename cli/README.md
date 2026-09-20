# DarkVault CLI

[![Release](https://img.shields.io/github/v/release/Bobsans/DarkVault)](https://github.com/Bobsans/DarkVault/releases/latest)
[![CI](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml/badge.svg)](https://github.com/Bobsans/DarkVault/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Bobsans/DarkVault/blob/main/LICENSE)

Manage secrets from your terminal or launch an application with a bucket loaded
into its environment. Uses HTTPS and JWE; no SDK integration is required.

## Install and connect

Download the CLI archive matching your OS and architecture from
[GitHub Releases](https://github.com/Bobsans/DarkVault/releases), extract it, and put
`darkvault` (`darkvault.exe` on Windows) on your PATH. Server and CLI archives are separate.

```sh
darkvault --version
darkvault config set server https://vault.example.com
darkvault config set token
darkvault token info
```

The token prompt is hidden. Create a token in the administrative UI with the
operation scopes and bucket access you need. Bucket arguments are names, not UUIDs.
Use `darkvault <command> --help` for flags.

## Configuration

```sh
darkvault config set timeout 10s
darkvault config set page-size 50
darkvault config get server
darkvault config list
darkvault config path
darkvault config unset token
```

`get` and `list` show saved settings, not merged runtime settings; tokens are masked.
`config set token --stdin` reads a token from stdin. The config stores the token on
disk with owner-only permissions; it is not an encrypted credential store.

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Server | `--server` | `DARKVAULT_SERVER` | Required |
| Token | `--token` / `--token-file` | `DARKVAULT_TOKEN` / `DARKVAULT_TOKEN_FILE` | Hidden prompt |
| Request timeout | `--timeout` | `DARKVAULT_TIMEOUT` | `30s`; range `1s`–`30s` |
| Page size | `--limit` on list commands | `DARKVAULT_PAGE_SIZE` | `100`; range 1–200 |
| Config path | `--config` | `DARKVAULT_CONFIG` | OS user config directory |

Precedence: explicit flags → nonempty environment variables → saved config → defaults.
`--token` and `--token-file` are mutually exclusive. In the environment, the token
file takes precedence over the token value. Avoid putting secrets in arguments.
Timeout covers discovery and the command together. HTTPS certificates must be trusted.

Default config locations:

- Windows: `%APPDATA%/darkvault/config.json`.
- Linux: `$XDG_CONFIG_HOME/darkvault/config.json`, otherwise `~/.config/darkvault/config.json`.
- macOS: `~/Library/Application Support/darkvault/config.json`.

## Buckets

| Command | Purpose |
| --- | --- |
| `bucket add <bucket> --description <text>` | Create a bucket |
| `bucket get <bucket>` | Read metadata and revision |
| `bucket list --limit 100 --cursor <cursor>` | Read one metadata page; omit cursor initially |
| `bucket read <bucket>` | Read the snapshot including secret values |
| `bucket update <bucket> --description <text> --revision <n>` | Change description |
| `bucket delete <bucket> --revision <n>` | Delete an empty bucket |
| `bucket delete <bucket> --revision <n> --recursive` | Delete the bucket and its secrets |

Reading a complete bucket requires `bucket:read`, `secret:read`, `secret:list`, and
a bucket grant. Listing returns `items` and `nextCursor`; repeat with that cursor
until it is null. Pages are not fetched automatically.

## Secrets

```sh
darkvault secret add app_prod Database:Url
darkvault secret list app_prod
darkvault secret get app_prod Database:Url
darkvault secret update app_prod Database:Url --revision 1
```

`add`, `update`, and `set` prompt without echo. For automation use `--stdin` and
pipe from a protected source. Values must be UTF-8 and at most 64 KiB. Stdin is
used verbatim, including trailing newlines.

| Command | Purpose |
| --- | --- |
| `secret add <bucket> <key>` | Create |
| `secret get <bucket> <key>` | Print raw value without an added newline |
| `secret list <bucket> --limit 100 --cursor <cursor>` | List metadata without values |
| `secret update <bucket> <key> --revision <n>` | Replace at the expected revision |
| `secret set <bucket> <key> --revision <n>` | Create if revision is 0, otherwise replace |
| `secret delete <bucket> <key> --revision <n>` | Delete at the expected revision |

Use revisions returned by your latest metadata read; `1` above is illustrative.
A stale revision fails. Fetch fresh bucket metadata before deleting a bucket after
secret changes. `set` defaults to revision 0, not unconditional overwrite.

Most operations print API JSON. `secret get` prints the secret itself, and
`bucket read` includes plaintext values: keep this output out of shared logs.
Only JSON is supported by `--format`.

## Run an application with secrets

```sh
darkvault exec \
    --bucket app_prod \
    --aspnet-keys \
    -- dotnet MyApp.dll
```

- Every secret becomes a child environment variable; no shell is inserted.
- `--aspnet-keys` maps `ConnectionStrings:Main` to `ConnectionStrings__Main`.
- Replacing an inherited variable requires `--overwrite-env`.
- Invalid names, NUL values, and name collisions fail before launch.
- `DARKVAULT_TOKEN` and `DARKVAULT_TOKEN_FILE` are removed from inherited variables.
- The child inherits stdin/stdout/stderr; its exit code is returned. Other CLI errors return 1.

The child can read its injected secrets. They are not hidden from the child or
privileged operating-system users.

## Errors and access

`token info` reports your scopes, grants, and expiry. Token issuance and revocation
belong to the administrative UI. On failure, check certificate trust, the HTTPS
origin, token expiry, scopes, bucket grant, and revision.
The underlying Go SDK does not retry automatically. After an uncertain write
failure, read current state before repeating it.

## Build from source

With Go 1.25+, from the repository root:

```sh
go -C cli build -trimpath -o ../artifacts/darkvault .
```

Use `../artifacts/darkvault.exe` on Windows. Build from the repository checkout:
the CLI uses a local module replacement for the shared Go SDK.

[DarkVault overview](https://github.com/Bobsans/DarkVault#readme) ·
[Go SDK](https://github.com/Bobsans/DarkVault/blob/main/clients/go/README.md) ·
[Issues](https://github.com/Bobsans/DarkVault/issues)
