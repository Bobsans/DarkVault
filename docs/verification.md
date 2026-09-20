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
Для .NET используются прямые пути к `.csproj`; список проектов задан в `tools/verify.ps1`.

## Покрытие

| Область            | Проверка                                                                                                       |
|--------------------|----------------------------------------------------------------------------------------------------------------|
| Бакеты и секреты   | CRUD, revisions, границы размеров, pagination                                                                  |
| Авторизация        | Scopes, изоляция бакетов, expiry, отзыв и grants создания                                                      |
| Протокол           | Строгие JSON-поля, JWE, повреждение тега, привязка ответа, replay                                              |
| Хранение           | Шифрование, ротация, backup/read-back, rollback при SQLITE_FULL                                                |
| C# SDK             | Реальный HTTPS, configuration provider и регистровые коллизии                                                  |
| Python SDK         | Все data-команды на сервере .NET, TLS, ошибки, revisions, JWE, пределы тела и безопасные повторы               |
| Go SDK             | Все data-операции на сервере .NET, TLS, revisions, pagination и публичный JWE fixture                          |
| TypeScript SDK     | Общий с UI JWE-модуль, все data-операции, revisions, pagination, отмена и границы транспорта                   |
| Go CLI             | Команды через общий Go SDK, безопасное окружение дочернего процесса                                            |
| Конфиг CLI         | Set/get/unset, маскировка токена, приоритеты, приватные права файла, запуск без параметров подключения         |
| Браузер            | Вход, создание бакета, изменение секрета, выдача/отзыв токена, выход                                           |
| SPA                | Строгая проверка TypeScript, упаковка HTML/CSS/JS с сервером, security headers и 404 для неизвестных API-путей |
| Межъязыковой обмен | Общий публичный fixture и обмен .NET ↔ Go / Python / браузер                                                   |

`tests/fixtures/jwe.json` содержит исключительно публичные тестовые ключи.
Тестовый сертификат не добавляется в системное хранилище доверия. Сервер стенда
останавливается в `finally`, его приватный каталог и descriptor удаляются.
Базы реальных установок не используются.

## Результаты и артефакты

- `artifacts/test-results/*.trx` — результаты .NET-тестов сервера и C#-клиента.
- `admin/test-results` — результат browser E2E и снимок интерфейса.
- `artifacts/server` — опубликованный сервер.
- `artifacts/darkvault.exe` — CLI для текущей ОС.
- `artifacts/packages` — NuGet-пакеты SDK и configuration extension.
- `artifacts/python` — wheel и исходный архив Python SDK.
- `artifacts/typescript` — npm-архив TypeScript SDK с ESM и декларациями типов.

Детальные команды запуска сервера и клиентов: [operations.md](operations.md).
Проверка публичного домена и автоматического продления HTTPS-сертификата выполняется
на реальном развёртывании; локальный стенд её не заменяет.

## Native AOT

Сервер поддерживает отдельный профиль `NativeAot`. JSON-контракты и обработчики
HTTP используют source generation; reflection-based JSON на сервере отключён
даже в обычной managed-сборке. Для JWE используются существующие реализации
ECDH-ES и AES-GCM из `jose-jwt` без его reflection-based JWT-сериализатора.
Формат HTTP/JWE и формат сохранённых данных не меняются.

Публикация для Windows x64:

```powershell
dotnet publish server/DarkVault.Server/DarkVault.Server.csproj -c Release -r win-x64 -p:PublishProfile=NativeAot -o artifacts/server-aot/win-x64 --disable-build-servers -warnaserror
```

Нужен нативный toolchain: Windows — Visual Studio с C++ desktop tools и Windows SDK;
Linux — clang и zlib development headers; macOS — Xcode command-line tools.
Полные требования: [документация Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).
AOT собирается на целевой ОС: для Linux используйте Linux и `-r linux-x64`,
для macOS — macOS и соответствующий RID. Поддержку конкретной архитектуры нужно
подтверждать на её toolchain, а не обычной cross-publish .NET.

Проверка нативного сервера для текущей ОС/архитектуры:

```powershell
pwsh tools/verify.ps1 -NativeAot
```

Сценарий публикует AOT с предупреждениями как ошибками, подготавливает временную
БД и сертификат через AcceptanceHost, затем запускает именно `DarkVault.Server`
из каталога публикации. C#, TypeScript, Go, Python и Playwright обращаются к этому
процессу; после остановки проверяются база, ротация ключей и повторное открытие.
Browser E2E включает audit и смену пароля. `-SkipInstall` допускается при уже
установленных зависимостях. CI выполняет этот режим на всех шести нативных runners.
`-Runtime` проверяет совпадение с ОС/архитектурой хоста; `-ReleaseTag v1.2.3`
подставляет версию и SHA до прогона тестов, чтобы упаковать тот же бинарник.

Готовому AOT-серверу не нужен установленный .NET. Поставляйте исполняемый файл,
нативную библиотеку SQLite и `wwwroot/` из publish-каталога вместе. `.pdb`/`.dbg`
и `.dSYM` — отладочные символы, для запуска не нужны. На macOS профиль сохраняет
символы в бинарнике (`StripSymbols=false`), обходя сбой `dsymutil` из-за отсутствующего
Clang module cache в статических библиотеках runtime; отдельный `.dSYM` не создаётся.
На Linux остаются зависимости
от системных библиотек .NET Native AOT; это не универсальный статический ELF.
Release-упаковка использует проверенные AOT-архивы всех шести RID. Матрица:

| RID           | GitHub runner      |
|---------------|--------------------|
| `linux-x64`   | `ubuntu-22.04`     |
| `linux-arm64` | `ubuntu-22.04-arm` |
| `win-x64`     | `windows-2025`     |
| `win-arm64`   | `windows-11-arm`   |
| `osx-x64`     | `macos-15-intel`   |
| `osx-arm64`   | `macos-15`         |

На Windows ARM64 Python-тесты используют x64-интерпретатор через эмуляцию;
сам AOT-сервер и .NET SDK используют ARM64. Linux собирается на Ubuntu 22.04,
чтобы не поднимать базовые требования системных библиотек до версии `ubuntu-latest`.

## Релизы по тегу

Push тега вида `v1.2.3` запускает `.github/workflows/release.yml`.
После успешных проверок Windows, Linux и macOS на x64 и ARM64
job `release` собирает и публикует GitHub Release с версией из тега:

- Сервер и CLI для Linux, Windows и macOS, каждый для x64 и ARM64.
  Windows получает ZIP, Linux и macOS — `tar.gz`. Сервер — Native AOT с SQLite и SPA,
  без установленного .NET и без отладочных символов.
- Два NuGet-пакета: `DarkVault.Client` и `DarkVault.Extensions.Configuration`.
- Python SDK: wheel и исходный архив sdist.
- Go SDK: архив самостоятельного модуля с исходниками и тестами.
- TypeScript SDK: npm-архив `.tgz` с JavaScript и декларациями типов.
- `release.json` с общей версией, SHA и версией протокола.
- `SHA256SUMS` для всех 18 пакетов и `release.json`.

Релиз становится публичным после загрузки всех файлов. Используется штатный
`GITHUB_TOKEN` с `contents: write`; отдельный токен не нужен. Затем независимые jobs
публикуют проверенные пакеты в PyPI, npm и NuGet.org через OIDC, без пересборки.
Настройка аккаунтов и первого выпуска: [publishing.md](publishing.md).
Поддерживаются стабильные теги `vMAJOR.MINOR.PATCH`.
Для Go SDK создаётся дополнительный тег `clients/go/vMAJOR.MINOR.PATCH` на том же
коммите: он делает версию доступной через `go get`. Исходный модуль использует
правила версионирования Go для v0/v1; переход SDK на v2 потребует изменения module path.

Упаковка одного проверенного RID: `pwsh tools/package-native-server.ps1 -Tag v1.2.3 -Runtime win-x64`.
Перед этим выполните `verify.ps1 -NativeAot -Runtime win-x64 -ReleaseTag v1.2.3` на Windows x64.
Собрав шесть архивов, выполните `pwsh tools/package-release.ps1 -Tag v1.2.3 -ServerAssets artifacts/native-assets`.
Нужны .NET 10 SDK, Go, Python с модулем `build`, Node.js 22+, pnpm 11 и `tar`. Результаты находятся в
`artifacts/releases/v1.2.3/assets`; каталог версии должен отсутствовать перед запуском.
Unix-архивы сервера собираются на соответствующих Linux/macOS runners с сохранением прав исполнения.
Версии Python и TypeScript меняются только на время упаковки и затем восстанавливаются.
Правила общей версии и проверки содержимого пакетов: [versioning.md](versioning.md).
