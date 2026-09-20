# DarkVault TypeScript SDK

Типизированный HTTPS/JWE-клиент для Node.js 22+ и браузерных сборщиков.
ESM JavaScript и декларации `.d.ts` поставляются вместе; runtime-зависимость — `jose`.

Установка npm-архива из GitHub Release:

```sh
npm install ./darkvault-client-1.0.0.tgz
```

```typescript
import { DarkVaultClient, DarkVaultError } from '@darkvault/client';

const client = new DarkVaultClient('https://vault.example.com', process.env.DARKVAULT_TOKEN!);
const secrets = await client.readBucket('app_qa');
// Pass secrets to the application configuration; do not log them.
```

## API

- Бакеты: `addBucket`, `getBucket`, `listBuckets`, `readBucket`, `readBucketSnapshot`,
  `updateBucket`, `deleteBucket`.
- Секреты: `addSecret`, `readSecret`, `listSecrets`, `updateSecret`, `setSecret`, `deleteSecret`.
- Токен: `getTokenInfo`.
- Низкоуровневый вызов: `execute<T>(operation, parameters, signal?)`.

`bucket` — точное имя, не UUID. Изменение и удаление требуют актуальную `revision`.
`setSecret` с revision `0` создаёт отсутствующий секрет. Revision — неотрицательное
безопасное целое JavaScript. Даты в DTO — строки ISO 8601.

Списки возвращают `Page<T>`: передайте `null` для первой страницы и limit от 1 до 200,
затем `nextCursor` для следующей; `null` означает конец списка.
`readBucket` возвращает `Record<string, string>`; `readBucketSnapshot` — также ID и revision.

Последний необязательный аргумент методов — `AbortSignal`. Discovery и запрос имеют
общий timeout: по умолчанию 30 секунд, настройка `{ timeoutMs: 5000 }` в конструкторе.
Автоматических повторов нет; при `request_outcome_unknown` проверьте состояние записи
перед повтором. Серверные ошибки — `DarkVaultError` с `code`, `status`, `requestId`.
`execute<T>` задаёт ожидаемый тип результата, но не является валидатором произвольной схемы `T`.

## Безопасность и браузер

TLS проверяется средой выполнения; редиректы и отправка cookies запрещены.
Токен передаётся только в `Authorization` data API, без хранения на диске или в localStorage.
Для частного CA в Node.js используйте `NODE_EXTRA_CA_CERTS` при запуске процесса.
Опция `fetch` позволяет передать собственную доверенную реализацию транспорта.

Не помещайте постоянные привилегированные токены в браузерный bundle. По умолчанию
сервер не предоставляет междоменные CORS-разрешения: browser SDK подходит для
same-origin сценария либо явно настроенного доверенного окружения.
Административный интерфейс использует общий `@darkvault/client/protocol`,
но сохраняет собственную cookie/CSRF-авторизацию.

## Разработка

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm pack
```

Интеграционный тест требует `DARKVAULT_ACCEPTANCE` с путём к descriptor тестового
сервера и его CA в `NODE_EXTRA_CA_CERTS`. Корневой `tools/verify.ps1` делает это автоматически.
Релизная job устанавливает версию из тега и прикладывает `.tgz` к GitHub Release;
публикации в npm registry нет.
