# Запуск DarkVault

Сервер работает одним процессом с SQLite. Новый процесс не запускается, если
каталог данных уже занят.

## Сборка

```powershell
pnpm --dir clients/typescript install --frozen-lockfile
pnpm --dir admin install --frozen-lockfile
dotnet build DarkVault.sln -c Release
dotnet test DarkVault.sln -c Release
dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release -o artifacts/server
dotnet pack clients/csharp/DarkVault.Client -c Release -o artifacts/packages
dotnet pack clients/csharp/DarkVault.Extensions.Configuration -c Release -o artifacts/packages
cd cli
go build -trimpath -o ../artifacts/cli/darkvault.exe .
```

Node 22+ и pnpm 11 нужны для сборки, но не для запуска готового сервера.
`dotnet build` и `dotnet publish` собирают TypeScript SDK и SPA из `admin/`, затем
включают HTML, CSS и JavaScript в выходной `wwwroot/`. Библиотеки JOSE входят
в bundle; CDN и отдельный frontend-сервер не нужны. `admin/dist/` не коммитится.
Команда генерации схем:
`python tools/generate-contract.py`.

Для публикации без установленного .NET используйте профиль `NativeAot`;
команды и требования toolchain описаны в [verification.md](verification.md#native-aot).
Нативный сервер запускается напрямую: `DarkVault.Server.exe serve` на Windows
или `./DarkVault.Server serve` на Unix. Команды bootstrap, verify, backup и ротации
те же; `wwwroot/` и нативная библиотека SQLite поставляются вместе с executable.

## Первичная настройка

Задайте `DARKVAULT_DATA` на отдельный приватный каталог. Не используйте корень
репозитория, домашний каталог или каталог с чужими данными: DarkVault ограничивает
его ACL текущим пользователем сервиса (Unix 0700 / Windows owner-only).

```powershell
$env:DARKVAULT_DATA = 'D:/DarkVaultData'
dotnet artifacts/server/DarkVault.Server.dll bootstrap
dotnet artifacts/server/DarkVault.Server.dll serve
```

Пароль вводится дважды, без echo, минимум 15 символов. Логин — `admin`.
CLI bootstrap требует локальный интерактивный терминал. Восстановление доступа:
остановить сервер и выполнить `reset-password`, затем запустить снова.
Пароль и токены нельзя передавать в аргументах процесса.

## Автоматический HTTPS

Укажите DNS A/AAAA домена на сервер, откройте 80/443 и запустите Caddy с
[Caddyfile](../deploy/Caddyfile), задав `DARKVAULT_DOMAIN=vault.example.com`.
Caddy получает и обновляет сертификат домена. DarkVault слушает только
`http://127.0.0.1:8866`; внешний plaintext HTTP запрещён приложением.
Проверка сертификатов SDK/CLI всегда включена, собственные CA-файлы не нужны.
Условия получения сертификата: [документация Automatic HTTPS](https://caddyserver.com/docs/automatic-https).

Не включайте логирование Authorization/тел запросов в proxy/APM и не подключайте
сторонние скрипты. Proxy доверенный: может видеть bearer-токен, даже если тело JWE.
Если proxy находится на другом хосте, нужен TLS до backend и точный список
`DARKVAULT_TRUSTED_PROXIES`; не открывайте незашифрованный backend в сеть.
Встроенный readiness `/health/ready` не раскрывает значения.

Шаблон systemd: [darkvault.service](../deploy/darkvault.service). Создайте отдельного
пользователя и принадлежащий ему `/var/lib/darkvault`; bootstrap выполняется этим же
пользователем. Релизный сервер скомпилирован Native AOT и не требует установки .NET.
Сохраните executable, нативную библиотеку SQLite и `wwwroot/` из архива вместе;
процесс может запускаться из другого cwd. Команды с `dotnet ...dll` в этом документе
относятся к обычной managed-сборке из исходников; для релиза запускайте
`./DarkVault.Server` (Windows: `./DarkVault.Server.exe`) с теми же аргументами.

## Бакет в C# / ASP.NET

```csharp
using DarkVault.Client;
using Microsoft.Extensions.Configuration;

using var client = new DarkVaultClient("https://vault.example.com", token);
var secrets = await client.ReadBucketAsync("app_qa", cancellationToken);
builder.Configuration.AddInMemoryCollection(secrets);
```

Или пакет `DarkVault.Extensions.Configuration`:

```csharp
await builder.Configuration.AddFromDarkVaultBucketAsync(
    "https://vault.example.com", token, "app_qa", cancellationToken);
```

Токен загружается из секретного источника приложения. Для чтения всего бакета нужны
`bucket:read`, `secret:read`, `secret:list` и доступ к выбранному бакету.
Последний provider имеет приоритет; вызовы AddEnvironmentVariables после DarkVault
могут переопределить значения. Загрузка однократная; ошибка останавливает запуск.
При передаче собственного HttpClient отключите AllowAutoRedirect и сохраните
стандартную TLS-проверку. SDK не уничтожает переданный HttpClient.

## CLI

Для Python-приложений доступен отдельный [Python SDK](../clients/python/README.md):
`python -m pip install ./clients/python`. Он получает сервер и токен явно и не
использует конфиг CLI автоматически.

Сохранение значений по умолчанию:

```text
darkvault config set server https://vault.example.com
darkvault config get server
darkvault config set token <token>
darkvault bucket read app_qa
```

`config set token` без аргумента использует скрытый ввод, а
`config set token --stdin` читает токен из stdin. Эти способы обходятся без
передачи токена через аргументы процесса и историю команд.

| Настройка | По умолчанию | Допустимые значения | Флаг / окружение |
| --- | --- | --- | --- |
| `server` | Не задан | HTTPS origin; имя без схемы получает `https://` | `--server` / `DARKVAULT_SERVER` |
| `token` | Не задан | Токен `dv1_`, ровно 64 символа | `--token` или `--token-file` / `DARKVAULT_TOKEN` или `DARKVAULT_TOKEN_FILE` |
| `timeout` | `30s` | От `1s` до `30s`, на discovery и команду вместе | `--timeout` / `DARKVAULT_TIMEOUT` |
| `page-size` | `100` | От 1 до 200 элементов списка | `--limit` / `DARKVAULT_PAGE_SIZE` |

```text
darkvault config set timeout 10s
darkvault config set page-size 50
darkvault config list
darkvault config unset token
darkvault config path
```

Приоритет подключения: явно заданные флаги → непустые переменные окружения →
конфиг → встроенные значения. `--token` и `--token-file` взаимоисключающие;
в окружении `DARKVAULT_TOKEN_FILE` имеет приоритет перед `DARKVAULT_TOKEN`.
Явно переданный пустой или неверный параметр вызывает ошибку, без скрытого fallback.
Если токен нигде не указан, CLI запрашивает его скрыто. `get` и `list` показывают
именно сохранённые настройки, без подстановки флагов и окружения; токен замаскирован.
`unset timeout` и `unset page-size` восстанавливают встроенные значения.

Путь по умолчанию: `%APPDATA%/darkvault/config.json` на Windows,
`$XDG_CONFIG_HOME/darkvault/config.json` или `~/.config/darkvault/config.json` на Linux,
`~/Library/Application Support/darkvault/config.json` на macOS.
Другой файл выбирается через `--config <path>` или `DARKVAULT_CONFIG`.
CLI создаёт JSON-файл с Unix-правами `0600` либо Windows DACL только для текущего
пользователя; токен внутри файла хранится без шифрования. При ошибке валидации/записи
предыдущий файл сохраняется; повреждённый конфиг не перезаписывается автоматически.
Отсутствующий файл означает, что действуют встроенные значения и окружение.

Разовые переопределения не изменяют сохранённые настройки:

```text
darkvault --server https://vault.example.com --token-file <private-file> bucket read app_qa
darkvault --server https://vault.example.com secret add app_qa ConnectionStrings:Main --stdin
darkvault --server https://vault.example.com secret get app_qa ConnectionStrings:Main
darkvault --server https://vault.example.com secret update app_qa ConnectionStrings:Main --revision 7 --stdin
darkvault --server https://vault.example.com exec --bucket app_qa --aspnet-keys -- dotnet App.dll
```

Списки имеют `--limit/--cursor`;
изменения требуют revision из предыдущего чтения. `set --revision 0` создаёт только
при отсутствии. `bucket delete --recursive --revision N` удаляет содержимое целиком.
`bucket read` выводит секреты открытым JSON только по явной команде пользователя.
`exec` запускает процесс без shell; не наследует переменные с токеном DarkVault.

## Backup, restore и ротация

Остановите сервис, затем `dotnet DarkVault.Server.dll backup <new-directory>`.
Команда использует SQLite backup API и копирует keyring. Защитите обе части:
доступ к keyring и БД вместе позволяет прочитать секреты. Не публикуйте архивы.

Для restore: остановить сервис, сохранить текущий каталог отдельно, восстановить
`vault.db` и `keyring.json` в новый приватный `DARKVAULT_DATA`, выполнить `verify`,
затем **`rotate-data` до первой записи**, затем запустить сервис. Копия не включает
активные сессии; нужно войти заново. После restore проверьте список токенов:
отзывы после даты backup не сохранены, при необходимости отзовите их повторно.

`rotate-data` сохраняет старые ключи и перешифровывает записи транзакциями;
повтор после сбоя безопасен, старые ключи не удаляются автоматически.
`rotate-transport` создаёт новый транспортный ключ; `--emergency` немедленно убирает
старые online ключи. При обычной смене старый ключ принимается до его notAfter + 10 минут.
API-токены меняются независимо: создать новый → переключить приложение → отозвать старый.

## Проверки

`tools/verify.ps1` собирает и проверяет .NET, Go, браузерный протокол и UI на временном
локальном HTTPS-стенде. Тестовый сертификат используется только тестами, не устанавливается
в системное хранилище доверия. Публичный `tests/fixtures/jwe.json` содержит исключительно
тестовые ключи. Реальное получение доменного сертификата требует настоящего
домена и доступных 80/443 и не доказывается локальным self-signed тестом.
