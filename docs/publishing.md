# Публикация пакетов

Workflow `.github/workflows/release.yml` проверяет изменения на Windows, Linux и macOS,
на каждой ОС отдельно для x64 и ARM64.
Только push стабильного тега `vMAJOR.MINOR.PATCH` запускает сборку релиза и публикацию.
Версии берутся из тега; manifests вручную менять не нужно.

Каждый runner собирает AOT-сервер и запускает SDK/browser-проверки на своей
архитектуре. Для тега в сборку сразу подставляются версия и SHA. Затем проверенный
executable, SQLite и SPA упаковываются без пересборки и без отладочных символов;
архив передаётся как `native-server-<RID>`. Job `release` требует успеха всех шести
проверок, скачивает архивы текущего workflow run и добавляет CLI/SDK и контрольные
суммы. Отсутствующий RID, другая версия/SHA или неверная архитектура останавливают выпуск.

| Компонент | Площадка | Имя |
| --- | --- | --- |
| Python SDK | PyPI | `darkvault-client` (импорт `darkvault`) |
| TypeScript SDK | npm | `@darkvault/client` |
| C# SDK | NuGet.org | `DarkVault.Client` |
| .NET configuration provider | NuGet.org | `DarkVault.Extensions.Configuration` |
| Go SDK | GitHub / Go module proxy | `github.com/Bobsans/DarkVault/clients/go` |
| Сервер и CLI | GitHub Releases | Архивы для Linux, Windows и macOS, x64/ARM64 |

Пакеты собираются один раз, проверяются `tools/check-release.py`, сохраняются
в artifact `registry-packages` и передаются jobs публикации без пересборки.
PyPI, npm и NuGet используют OIDC. Постоянные API-токены в GitHub не нужны.

## GitHub: общая настройка

1. В `Bobsans/DarkVault` откройте Settings → Environments → New environment.
   Создайте окружение с точным именем `release`.
2. В Deployment branches and tags выберите Selected branches and tags и добавьте
   правило **Tag** `v*`. Ограничение только веткой `main` не пропустит запуск по тегу.
3. В этом окружении добавьте **variable**, не secret: `NUGET_USER` — имя вашего
   аккаунта на nuget.org, не email. Не предполагается, что оно совпадает с GitHub.
4. Разрешите GitHub Actions и используемые workflow actions. При наличии rulesets
   для тегов разрешите workflow создание `clients/go/v*`.
5. Сохраните изменения workflow в GitHub до выпуска тега. Если branch protection
   требует старые checks, проверьте их имена после переименования workflow.

Jobs публикации используют `environment: release` и `id-token: write`.
Job создания GitHub Release использует штатный `GITHUB_TOKEN` с `contents: write`.
Если настроены required reviewers, соответствующие jobs будут ожидать подтверждения.

## PyPI: первый и последующие выпуски

Войдите на [PyPI](https://pypi.org/), подтвердите email и настройте 2FA.
Для нового проекта откройте [Publishing](https://pypi.org/manage/account/publishing/)
и добавьте pending publisher:

| Поле | Значение |
| --- | --- |
| PyPI Project Name | `darkvault-client` |
| Owner | `Bobsans` |
| Repository name | `DarkVault` |
| Workflow name | `release.yml` |
| Environment name | `release` |

Имя `darkvault` здесь неверно: оно не совпадает с `project.name` Python-пакета.
Pending publisher создаст `darkvault-client` при первой успешной публикации,
если имя доступно. Он не резервирует имя. Если проект уже существует и принадлежит
вам, добавьте publisher в настройках самого проекта. Чужое имя использовать нельзя.

Workflow публикует wheel и sdist официальным `pypa/gh-action-pypi-publish`.
После первого выпуска: `python -m pip install darkvault-client`.
[Документация PyPI](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## NuGet.org: оба .NET-пакета

Войдите на [nuget.org](https://www.nuget.org/) и откройте профиль → Trusted Publishing.
Создайте policy с Repository Owner `Bobsans`, Repository `DarkVault`, Workflow File
`release.yml`, Environment `release`. Владелец policy — аккаунт или организация,
которым должны принадлежать пакеты.

Разрешите **создание новых пакетов и новых версий**. Ограничьте пакеты шаблоном
`DarkVault.*`, либо точными именами `DarkVault.Client` и
`DarkVault.Extensions.Configuration`, если UI позволяет выбрать их.
Существующие пакеты должны принадлежать выбранному владельцу.

В GitHub environment `release` переменная `NUGET_USER` должна содержать имя
пользователя nuget.org, который создал policy. `NuGet/login@v1` получает временный
API key и публикует оба `.nupkg`. Ручная первая загрузка для OIDC не требуется,
если policy разрешает создание новых пакетов.

После выпуска:

```sh
dotnet add package DarkVault.Client
dotnet add package DarkVault.Extensions.Configuration
```

[Документация NuGet](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing).

## npm: namespace, первая публикация и OIDC

1. Создайте аккаунт на [npm](https://www.npmjs.com/), подтвердите email и включите 2FA.
2. Для имени `@darkvault/client` нужна организация/scope `darkvault` и право
   публикации под ней. Создайте организацию либо получите доступ к существующей.
   Свободность scope и права владения автоматически не проверяются этим репозиторием.
3. Если пакет уже существует и принадлежит вам, сразу настройте Trusted Publisher
   в Package → Settings. Для нового пакета сначала нужна одна ручная публикация:
   официальный `npm trust` требует уже существующий пакет.

### Первый npm-выпуск

После подготовки PyPI и NuGet запустите первый релиз по тегу. GitHub Release и
другие площадки публикуются независимо; npm job ожидаемо завершится ошибкой,
пока пакет и доверие не созданы. Скачайте именно npm-архив этого GitHub Release.
Например, для фактически выпущенного `v1.0.0`:

```powershell
gh release download v1.0.0 --repo Bobsans/DarkVault --pattern darkvault-client-1.0.0.tgz --dir artifacts/npm-bootstrap
npm login
npm publish ./artifacts/npm-bootstrap/darkvault-client-1.0.0.tgz --access public --ignore-scripts --registry=https://registry.npmjs.org
```

Выполняйте вход и 2FA в своём терминале. Используйте готовый архив с реальной
версией из тега; не публикуйте исходную папку с `0.0.0-dev`.

Теперь откройте `@darkvault/client` → Settings → Trusted publishing → GitHub Actions:

| Поле | Значение |
| --- | --- |
| Organization or user | `Bobsans` |
| Repository | `DarkVault` |
| Workflow filename | `release.yml` |
| Environment | `release` |
| Allowed actions | Разрешить `npm publish` |

Одного разрешения `npm stage publish` недостаточно: workflow публикует напрямую.
Вернитесь в GitHub Actions и выберите **Re-run failed jobs**. npm job проверит
SHA-512 уже опубликованного архива и завершится успешно при полном совпадении.
Следующий тег публикуется автоматически через OIDC. После первой автоматической
публикации можно включить npm Publishing access → Require 2FA and disallow tokens.

Workflow устанавливает npm 11 с поддержкой OIDC и Node.js 22. Локально для
`npm trust` нужен npm 11.15.0+, а для автоматической публикации — 11.5.1+.
Установка SDK после выпуска: `npm install @darkvault/client`.

[OIDC npm](https://docs.npmjs.com/trusted-publishers/),
[условия первой настройки](https://docs.npmjs.com/cli/v11/commands/npm-trust/).

## Go SDK, сервер и CLI

Отдельный аккаунт на Go proxy не нужен. Workflow создаёт тег
`clients/go/vMAJOR.MINOR.PATCH` на том же коммите, что и основной тег.
Публичный GitHub-репозиторий, корректный `go.mod` и этот тег позволяют получить модуль:

```sh
go get github.com/Bobsans/DarkVault/clients/go@v1.0.0
```

Появление в proxy и pkg.go.dev может запаздывать. При необходимости запросите
конкретную версию через `go list -m github.com/Bobsans/DarkVault/clients/go@v1.0.0`
или откройте страницу модуля на pkg.go.dev. [Публикация Go-модулей](https://go.dev/doc/modules/publishing).
Сервер и CLI скачиваются из GitHub Releases; публикация в Docker Hub, winget,
Chocolatey и Homebrew в этот workflow не входит.

## Выпуск и восстановление после ошибки

После проверки и коммита изменений отправьте новый стабильный тег, например:

```sh
git tag v1.0.0
git push origin v1.0.0
```

Это пример команды публикации, а не команда подготовки: push тега запускает
реальные внешние загрузки. Все аккаунты и имена должны быть настроены заранее,
кроме описанного выше первого npm-выпуска.

При сбое registry job исправьте настройку площадки и используйте **Re-run failed jobs**.
Не запускайте заново успешную job `release`: GitHub Release и Go-тег уже существуют.
PyPI пропускает существующие файлы, NuGet — дубликаты версий, npm — только
архив с совпадающим SHA-512. Сбой авторизации или сети npm не считается отсутствием пакета.
Результаты успешных публикаций не откатываются при сбое другой площадки.
Не перемещайте выпущенные теги; изменение кода требует нового тега.

Если artifact `registry-packages` уже истёк, автоматический повтор не сможет его
скачать. Сохранённые файлы есть в GitHub Release; не пересобирайте ту же версию
для замены опубликованных пакетов.
