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

Интерфейс использует один маршрут `/`, переключая экраны в браузере. Неизвестные
API-пути и отсутствующие ресурсы возвращают 404, а не HTML. Login/logout, смена
пароля, cookie-сессии и CSRF остаются серверными API.

Полная проверка: `pwsh tools/verify.ps1`. Она запускает HTTPS AcceptanceHost с
временным состоянием и выполняет browser E2E из `admin/e2e/`.
