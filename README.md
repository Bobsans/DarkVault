# DarkVault

Хранилище секретов с административным веб-интерфейсом, бакетами и токенами доступа.
Сервер — ASP.NET Core и SQLite; клиенты — C# SDK, Python SDK и CLI на Go.
Проект находится в разработке и ещё не опубликован.

## Возможности

- Вход суперадминистратора, управление бакетами, секретами и токенами.
- Токены длиной 64 символа: scopes, разрешённые бакеты, срок действия или бессрочный доступ, отзыв.
- Чтение целого бакета для конфигурации приложения.
- HTTPS и дополнительное JWE-шифрование запросов/ответов; AES-GCM для хранения.
- Независимые ключи хранения и доступа, ротация, backup/restore и аудит.

## Сборка и запуск

Нужны .NET 10 SDK, Go 1.25+; для изменения веб-интерфейса — Node.js 22+ и pnpm 11.
Собранный браузерный модуль хранится в репозитории, обычная сборка сервера не требует Node.

```powershell
dotnet build DarkVault.sln -c Release
$env:DARKVAULT_DATA = 'D:/DarkVaultData'
dotnet run --project server/DarkVault.Server -- bootstrap
dotnet run --project server/DarkVault.Server -- serve
```

`bootstrap` запрашивает пароль локально без отображения на экране. Логин — `admin`.
Перед сервером нужен HTTPS reverse proxy: [Caddyfile](deploy/Caddyfile) автоматически
получает сертификат публичного домена. Подробности: [инструкция запуска](docs/operations.md).

## C# / ASP.NET Core

```csharp
using DarkVault.Client;

using var client = new DarkVaultClient("https://vault.example.com", token);
var secrets = await client.ReadBucketAsync("app_qa", cancellationToken);
builder.Configuration.AddInMemoryCollection(secrets);
```

Или с `DarkVault.Extensions.Configuration`:

```csharp
await builder.Configuration.AddFromDarkVaultBucketAsync(
    "https://vault.example.com", token, "app_qa", cancellationToken);
```

Токен загружается из секретного источника приложения. Для чтения бакета нужны
`bucket:read`, `secret:read`, `secret:list` и доступ к выбранному бакету.
Пример приложения: [samples/AspNet](samples/AspNet).

## Python

```bash
python -m pip install ./clients/python
```

```python
from darkvault import DarkVaultClient

with DarkVaultClient("https://vault.example.com", token) as vault:
    secrets = vault.read_bucket("app_qa")
```

Python 3.11+, все операции с бакетами и секретами, pagination, revisions и
безопасные ошибки. [Документация Python SDK](clients/python/README.md).

## CLI

```powershell
New-Item -ItemType Directory -Force artifacts | Out-Null
Push-Location cli
go build -o ../artifacts/darkvault.exe .
Pop-Location
./artifacts/darkvault.exe config set server https://vault.example.com
./artifacts/darkvault.exe config set token
./artifacts/darkvault.exe bucket read app_qa
```

Команды: `bucket add|get|list|read|update|delete`,
`secret add|get|list|update|set|delete`, `token info`, `exec`, `config`.
`config set token` без значения запрашивает токен скрыто; поддерживается и
`config set token <token>`. `config get server` показывает сохранённый сервер,
`config list` — настройки с замаскированным токеном.

Приоритет: флаги → окружение → конфиг. Дополнительные настройки:
`config set timeout 10s`, `config set page-size 50`.
Путь к файлу: `config path`; сброс отдельного значения: `config unset <key>`.
Подробности хранения и всех переопределений: [конфигурация CLI](docs/operations.md#cli).

## Проверка

```powershell
pwsh tools/verify.ps1
```

Сценарий проверяет сервер, SDK, CLI и UI, затем собирает локальные артефакты.
[Подробности проверок](docs/verification.md).

## Документация

- [Спецификация](docs/specification.md)
- [HTTP/JWE-протокол](docs/protocol.md) и [OpenAPI](docs/openapi.json)
- [Запуск, конфигурация, backup/restore](docs/operations.md)

Сервер расшифровывает значения в памяти и доверяет своему HTTPS proxy; это не
zero-knowledge хранилище. Ключи и база должны храниться в приватном каталоге сервиса.
