# Проверка проекта

```powershell
pwsh tools/verify.ps1
```

Требования: .NET 10 SDK, Go 1.25+, Python 3.11+, Node.js 22+, pnpm 11 и PowerShell 7.
Для уже установленных frontend-зависимостей можно передать `-SkipInstall`;
параметры `-Node`, `-Pnpm` и `-Python` позволяют указать путь к инструментам.
Для сборки Python создаётся `artifacts/python-env`, а wheel устанавливается
в отдельное `artifacts/python-consumer`. Тесты запускаются из установленного пакета.

Сценарий собирает сервер и C# SDK, проверяет форматирование, запускает .NET-тесты,
Go-тесты и vet, Python-тесты, JavaScript-тесты протокола и Playwright на отдельном
локальном HTTPS-сервере. Затем публикует сервер, собирает NuGet-пакеты и Python wheel/sdist в `artifacts`.

## Покрытие

| Область | Проверка |
| --- | --- |
| Бакеты и секреты | CRUD, revisions, границы размеров, pagination |
| Авторизация | Scopes, изоляция бакетов, expiry, отзыв и grants создания |
| Протокол | Строгие JSON-поля, JWE, повреждение тега, привязка ответа, replay |
| Хранение | Шифрование, ротация, backup/read-back, rollback при SQLITE_FULL |
| C# SDK | Реальный HTTPS, configuration provider и регистровые коллизии |
| Python SDK | Все data-команды на сервере .NET, TLS, ошибки, revisions, JWE, пределы тела и безопасные повторы |
| Go SDK | Все data-операции на сервере .NET, TLS, revisions, pagination и публичный JWE fixture |
| TypeScript SDK | Общий с UI JWE-модуль, все data-операции, revisions, pagination, отмена и границы транспорта |
| Go CLI | Команды через общий Go SDK, безопасное окружение дочернего процесса |
| Конфиг CLI | Set/get/unset, маскировка токена, приоритеты, приватные права файла, запуск без параметров подключения |
| Браузер | Вход, создание бакета, изменение секрета, выдача/отзыв токена, выход |
| Межъязыковой обмен | Общий публичный fixture и обмен .NET ↔ Go / Python / браузер |

`tests/fixtures/jwe.json` содержит исключительно публичные тестовые ключи.
Тестовый сертификат не добавляется в системное хранилище доверия. Сервер стенда
останавливается в `finally`, его приватный каталог и descriptor удаляются.
Базы реальных установок не используются.

## Результаты и артефакты

- `artifacts/test-results/*.trx` — результаты .NET-тестов сервера и C#-клиента.
- `server/DarkVault.Server/Web/test-results` — результат browser E2E и снимок интерфейса.
- `artifacts/server` — опубликованный сервер.
- `artifacts/darkvault.exe` — CLI для текущей ОС.
- `artifacts/packages` — NuGet-пакеты SDK и configuration extension.
- `artifacts/python` — wheel и исходный архив Python SDK.
- `artifacts/typescript` — npm-архив TypeScript SDK с ESM и декларациями типов.

Детальные команды запуска сервера и клиентов: [operations.md](operations.md).
Проверка публичного домена и автоматического продления HTTPS-сертификата выполняется
на реальном развёртывании; локальный стенд её не заменяет.

## Релизы по тегу

Push тега вида `v1.2.3` запускает CI. После успешных проверок на Linux и Windows
job `release` собирает и публикует GitHub Release с версией из тега:

- Сервер и CLI для Linux, Windows и macOS, каждый для x64 и ARM64.
  Windows получает ZIP, Linux и macOS — `tar.gz`. Сервер включает .NET runtime.
- Два NuGet-пакета: `DarkVault.Client` и `DarkVault.Extensions.Configuration`.
- Python SDK: wheel и исходный архив sdist.
- Go SDK: архив самостоятельного модуля с исходниками и тестами.
- TypeScript SDK: npm-архив `.tgz` с JavaScript и декларациями типов.
- `release.json` с общей версией, SHA и версией протокола.
- `SHA256SUMS` для всех 18 пакетов и `release.json`.

Релиз становится публичным после загрузки всех файлов. Используется штатный
`GITHUB_TOKEN` с `contents: write`; отдельный токен не нужен. NuGet.org, PyPI и npm registry
этим workflow не публикуются. Поддерживаются стабильные теги `vMAJOR.MINOR.PATCH`.
Для Go SDK создаётся дополнительный тег `clients/go/vMAJOR.MINOR.PATCH` на том же
коммите: он делает версию доступной через `go get`. Исходный модуль использует
правила версионирования Go для v0/v1; переход SDK на v2 потребует изменения module path.

Упаковку можно проверить локально: `pwsh tools/package-release.ps1 -Tag v1.2.3`.
Нужны .NET 10 SDK, Go, Python с модулем `build`, Node.js 22+, pnpm 11 и `tar`. Результаты находятся в
`artifacts/releases/v1.2.3/assets`; каталог версии должен отсутствовать перед запуском.
Unix-архивы для выпуска собираются на Linux, чтобы сохранить права исполняемых файлов.
Версии Python и TypeScript меняются только на время упаковки и затем восстанавливаются.
Правила общей версии и проверки содержимого пакетов: [versioning.md](versioning.md).
