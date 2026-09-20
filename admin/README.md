# DarkVault Admin

Небольшое TypeScript SPA без UI-фреймворка. `index.html` и `style.css` — оболочка,
`src/app.ts` — интерфейс, `src/protocol.ts` — cookie/CSRF-транспорт поверх общего
JWE-модуля `@darkvault/client`. Секреты передаются через существующий зашифрованный API.

Из корня репозитория:

```powershell
pnpm --dir clients/typescript install --frozen-lockfile
pnpm --dir admin install --frozen-lockfile
pnpm --dir clients/typescript build
pnpm --dir admin build
pnpm --dir admin test
```

`dotnet build` и `dotnet publish` сервера сами собирают SDK и SPA и копируют
`index.html`, `app.js`, `style.css` в `wwwroot` выходного каталога. Зависимости нужно
установить перед первой сборкой. `dist/` не коммитится; Node.js и pnpm нужны только
для сборки, готовый сервер обслуживает SPA сам, без отдельного frontend-процесса.

Навигация использует History API (`pushState`/`popstate`), без hash-маршрутов:
`/admin/buckets`, `/admin/buckets/{name}`, `/admin/tokens`, `/admin/logs`,
`/admin/settings`. Корень `/` открывает список бакетов. Прямой переход и refresh
сохраняют страницу, в том числе после входа. Сервер отдаёт HTML только для этих
UI-маршрутов; неизвестные API-пути и отсутствующие ресурсы возвращают 404.
Login/logout, смена пароля, cookie-сессии и CSRF остаются серверными API.

Activity logs показывает события таблицей с раскрытием метаданных. Поиск,
тип события и результат фильтруются сервером по всей истории, а не только
по загруженной странице; фильтры сохраняются в query string. События идут от новых
к старым; Refresh загружает свежие события, Load older events продолжает выборку.
Значения секретов очищаются при закрытии диалога, навигации и выходе; в URL,
history state и localStorage они не сохраняются.

Интерфейс адаптируется под телефон, поддерживает клавиатуру, видимый focus,
aria-current в навигации и aria-expanded у деталей событий. Таблица логов на
узком экране прокручивается внутри своего контейнера.

Полная проверка: `pwsh tools/verify.ps1`. Она запускает HTTPS AcceptanceHost с
временным состоянием и выполняет browser E2E из `admin/e2e/`.

В Secrets можно выбрать string/number/boolean/null. Configuration показывает
структуру бакета, а после явного Reveal — JSON/YAML с сохранением типов, копированием
и скачиванием. Правила путей и ограничений: [configuration](../docs/configuration.md).
