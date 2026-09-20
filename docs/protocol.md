# DarkVault HTTP protocol v1

Дата: 2026-09-19. Связанная [спецификация продукта](specification.md).
Этот документ описывает HTTP/JWE-протокол сервера и клиентов.
Названия полей, формат токена, правила авторизации и ошибки одинаковы для всех языков.

## 1. Транспорт и идентификация

Только HTTPS с проверкой hostname и доверенной цепочки. Сертификат домена
автоматически обновляет reverse proxy; клиентские сертификаты не нужны.
URL credentials, query-токены, HTTP downgrade и redirect запрещены.

Data API требует `Authorization: Bearer <token>` на каждом запросе.
Cookie не принимается. Для браузера выделен `/admin/api/v1` с сессией и CSRF;
его execute endpoint использует такой же криптографический envelope, но отдельный audience.
Одновременная передача cookie и bearer не объединяет права: применяется только
схема соответствующего endpoint, неподходящая схема не является fallback.

Поддерживаемый профиль: HTTP API `/api/v1`, токены `dv1_`, envelope `v = 1`. Неизвестные форматы отклоняются.

## 2. Публичный ключ и JWE

`GET /api/v1/crypto/key` возвращает текущие `protocolVersion`, `serverId`,
`serverTime`, `kid`, `publicKey` (JWK), `notAfter` и опубликованные лимиты.
Endpoint публичный, rate-limited, не раскрывает секретов и закрытых частей ключа.
`serverId` — стабильный UUID установки, не URL. Ключ действителен 30 дней;
serverTime используется для диагностики, не для безусловного отключения проверки часов.
Клиент кэширует ключ максимум 5 минут и не дольше `notAfter`.

Фиксированный криптографический профиль:

| Параметр          | Значение                                     |
|-------------------|----------------------------------------------|
| Формат            | JWE Compact Serialization, пять сегментов    |
| Управление ключом | `alg = ECDH-ES`                              |
| Шифрование        | `enc = A256GCM`                              |
| Кривая            | P-256                                        |
| Public key        | JWK `kty=EC`, `crv=P-256`, `x`, `y`; без `d` |
| GCM IV / tag      | 96 / 128 бит                                 |
| Кодирование       | UTF-8 JSON; binary — base64url без padding   |

Применяется стандартная Concat KDF из JWA, не HKDF и не хеширование строки токена.
Заголовок полностью protected; `alg`, `enc`, `epk`, `kid`, `typ`, `cty` обязательны.
`cty = application/json`; `apu`/`apv` отсутствуют. Для ECDH-ES сегмент encrypted key
пустой. AEAD AAD задаётся стандартным JWE protected header.
Каждый envelope получает новую ephemeral ECDH key pair и новый IV.
`epk` — ключ отправителя для одного JWE; его нельзя путать с `replyKey` получателя ответа.

Сжатие `zip`, другие алгоритмы/кривые, unprotected headers, `jku`/`x5u`, закрытые JWK
в запросах и неизвестные `crit` запрещены. Проверяются корректность точки P-256,
фиксированные размеры координат и отсутствие повторяющихся полей JSON.
Не писать вручную ECDH/KDF/JWE: использовать поддерживаемую JOSE-библиотеку.
Совместимость библиотек .NET/Go/Python/browser проверяется общим тестовым вектором.

Основания стандартного формата: [JWE, RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
и [JWA, RFC 7518 §4.6, §5.3](https://www.rfc-editor.org/rfc/rfc7518.html).
Поля приложения и ограничения ниже — собственный профиль DarkVault поверх JWE.

## 3. Запрос и ответ

Все операции данных идут через `POST /api/v1/execute` с
`Content-Type: application/jose` и `Accept: application/jose`.
Единый endpoint позволяет скрывать в ciphertext имена бакетов/ключей, параметры
команд и публичный ключ ответа. Это небольшой RPC API, не набор GET с телами.

Клиент получает server JWK по HTTPS, создаёт отдельную временную P-256 пару для
ответа, формирует payload, затем шифрует его для server JWK. В protected header
запроса: `kid` серверного ключа, `typ = darkvault-request+jwe`.

Пример расшифрованного запроса (на сети передаётся только JWE):

```json
{
  "v": 1,
  "requestId": "2d33f7a2-8038-42eb-845c-d51b5246ad79",
  "issuedAt": "2026-09-19T10:00:00Z",
  "serverId": "0febdc65-9736-4aeb-b24c-9da5b7e72b5b",
  "audience": "data",
  "operation": "bucket.read",
  "parameters": { "bucket": "app_qa" },
  "replyKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url-32-byte-coordinate>",
    "y": "<base64url-32-byte-coordinate>"
  }
}
```

Placeholder-координаты иллюстративны и не являются тестовым вектором.
`requestId` — случайный UUIDv4, новый для каждой попытки; `issuedAt` — UTC с `Z`.
Сервер принимает возраст до 60 секунд и опережение часов до 30 секунд.
`serverId`, audience и тип сообщения должны соответствовать endpoint.

Порядок обработки: лимиты → bearer/session → разбор разрешённого JWE → decrypt →
валидация payload/времени → проверка scopes и bucket ACL → резервирование requestId
→ операция → ответ. Нельзя выдавать значения до полной проверки тега.

Сервер шифрует ответ для `replyKey` из этого запроса. Protected header ответа:
`typ = darkvault-response+jwe`, `kid = requestId`, остальные параметры профиля те же.
Ключ ответа не регистрируется как постоянный ключ клиента. После завершения
операции клиент освобождает временный private key; не пишет его на диск.

```json
{
  "v": 1,
  "requestId": "2d33f7a2-8038-42eb-845c-d51b5246ad79",
  "serverId": "0febdc65-9736-4aeb-b24c-9da5b7e72b5b",
  "audience": "data",
  "operation": "bucket.read",
  "status": 200,
  "data": {
    "bucketId": "e711cd17-42cd-4415-a2cf-3a9f955552bb",
    "revision": 7,
    "secrets": { "ConnectionStrings:Main": "<secret-value>" }
  },
  "error": null
}
```

Клиент проверяет authenticated decrypt, v, тип, kid, requestId, serverId, audience,
operation и совпадение внутреннего status с HTTP status. Ответ принимается один раз,
только для незавершённого запроса. Ошибка декодирования не даёт частичного результата.
Серверная аутентификация ответа опирается на HTTPS: JWE сам по себе не подпись отправителя.

## 4. Replay, retries и ключи

Сервер хранит уникальную пару `(principalId, requestId)` в SQLite до
`issuedAt + 90 seconds`. Запись резервируется атомарно до выполнения; повтор
получает `409 replay_detected`, включая параллельный запрос. При перезапуске
данные не теряются. Откат транзакции не должен удалять уже принятое replay-резервирование.
Principal для администратора — account ID, для клиента — token ID.

Это защита от повторного выполнения одного envelope, не обещание exactly-once.
Если ответ на изменение потерян, SDK возвращает ошибку неопределённого результата;
проверка текущего объекта выполняется явно. Новый requestId не делает повтор мутации
безопасным. Revisions и создание только при отсутствии защищают от тихой перезаписи.
Чтения можно повторить максимум два раза с новым envelope; `429` учитывает Retry-After.

Транспортный private key хранится вне БД с ограниченными правами, отдельно от
storage keyring. Плановая ротация сохраняет предыдущий ключ для decrypt 10 минут
после его notAfter, затем удаляет его из online keyring. При компрометации grace
не применяется. `unknown_key` возвращается до выполнения команды; клиент может
однократно обновить публичный ключ и заново сформировать запрос, включая мутацию.
Этот случай отличается от сетевого таймаута после возможной записи.

Постоянный серверный ECDH private key может позволить расшифровать записанные ранее
JWE-запросы при его последующей утечке. Дополнительный слой не обещает forward secrecy
для запросов; HTTPS обеспечивает свои транспортные свойства независимо.

## 5. Операции и JSON-схемы

Схемы опубликованы в [openapi.json](openapi.json), включая plaintext-модели под JWE.
Таблица ниже — их семантическое основание. Поля, отмеченные `?`, необязательны.
UUID, даты и имена — строки; revision — целое 0..9007199254740991 для совместимости
с JavaScript, переполнение запрещено. Входные неизвестные поля отклоняются;
клиенты могут игнорировать дополнительные поля успешного ответа v1.

| operation       | parameters                                   | data                                         |
|-----------------|----------------------------------------------|----------------------------------------------|
| `bucket.create` | `name`, `description?`                       | Bucket                                       |
| `bucket.get`    | `bucket`                                     | Bucket                                       |
| `bucket.list`   | `cursor?`, `limit?`                          | `items: Bucket[]`, `nextCursor`              |
| `bucket.read`   | `bucket`                                     | `bucketId`, `revision`, `secrets` dictionary |
| `bucket.update` | `bucket`, `description`, `expectedRevision`  | Bucket                                       |
| `bucket.delete` | `bucket`, `expectedRevision`, `recursive?`   | `deleted: true`                              |
| `secret.create` | `bucket`, `key`, `value`                     | SecretMetadata                               |
| `secret.read`   | `bucket`, `key`                              | SecretMetadata + `value`                     |
| `secret.list`   | `bucket`, `cursor?`, `limit?`                | `items: SecretMetadata[]`, `nextCursor`      |
| `secret.update` | `bucket`, `key`, `value`, `expectedRevision` | SecretMetadata                               |
| `secret.set`    | `bucket`, `key`, `value`, `expectedRevision` | SecretMetadata                               |
| `secret.delete` | `bucket`, `key`, `expectedRevision`          | `deleted: true`                              |
| `token.info`    | empty object                                 | TokenInfo                                    |

`bucket` — точное имя, разрешаемое в UUID до проверки ACL; не union имени/ID.
Bucket: `id`, `name`, `description`, `revision`, `createdAt`, `updatedAt`.
SecretMetadata: `id`, `bucketId`, `key`, `revision`, `createdAt`, `updatedAt`.
TokenInfo: `id`, `name`, `scopes`, `bucketIds`, `allBuckets`,
`creatableBucketNames`, `expiresAt`; без hash и полного токена.
`description` по умолчанию пустая строка, максимум 1024 байта UTF-8;
`recursive` по умолчанию false, `nextCursor` при завершении равен null.
Revisions берутся из сохраняемого монотонного счётчика БД, начинающегося с 1.
Одна мутация атомарно получает новую revision и присваивает её изменённому объекту
и его бакету. Повторное создание не сбрасывает revision: это исключает применение
устаревшего запроса к новому объекту с прежним именем. 0 зарезервирован для create-if-absent.
Удаление отсутствующего объекта возвращает 404.
Создание возвращает 201, остальные успехи 200; ответ всегда имеет envelope.

В admin execute дополнительно доступны `token.create`, `token.list`, `token.revoke`,
`audit.list`. `token.create` принимает name, scopes, ограничения бакетов, expiresAt
и возвращает metadata + полный token один раз в зашифрованном ответе.
Потеря ответа не позволяет повторно получить токен: его нужно отозвать по ID из списка
и создать новый. `token.revoke` принимает token ID и идемпотентно отзывает его.
Схемы admin-команд и login/logout включены в OpenAPI;
они не являются публичным SDK-контрактом.

## 6. Ошибки и лимиты

Расшифрованная ошибка: `v`, `requestId`, `serverId`, `audience`, `operation`,
`status`, `data: null`, `error: { code, message }`.
message безопасен для пользователя; код стабилен и не зависит от языка текста.

| HTTP    | code / условие                                                                                 |
|---------|------------------------------------------------------------------------------------------------|
| 400     | `invalid_request`, `invalid_envelope`, `unsupported_version`, `unknown_key`, `request_expired` |
| 401     | `unauthorized`: отсутствующий, неверный, истёкший или отозванный токен                         |
| 403     | `forbidden`: нет scope для доступного ресурса                                                  |
| 404     | `not_found`: объект отсутствует или бакет недоступен этому токену                              |
| 409     | `already_exists`, `revision_conflict`, `bucket_not_empty`, `replay_detected`                   |
| 413     | `payload_too_large`                                                                            |
| 429     | `rate_limited` + Retry-After                                                                   |
| 500/503 | `internal_error` / `unavailable`, без stack trace                                              |

Не раскрывать существование чужих бакетов через различие 403/404. Для create
конфликт допустимого имени возвращает 409, без владельца и метаданных чужого бакета.
`bucket.list` не показывает чужие бакеты. Detailed auth errors доступны только аудиту.

До получения проверенного replyKey сервер может вернуть незашифрованный JSON
`{ "error": { "code": "unauthorized", "message": "Request rejected." } }`.
Такой ответ не содержит data, значений, токена, имён объектов и не является успехом.
После проверки envelope прикладные ответы, включая ошибки ACL/CRUD, шифруются.
HTTP-ошибки proxy могут быть без envelope; SDK обрабатывает их как транспортные,
не выводит сырое тело и никогда не принимает незашифрованный успешный ответ.

Лимиты по умолчанию: 2 МиБ HTTP request/response, 1536 КиБ расшифрованного JSON,
глубина JSON 16, одна операция на запрос, общий deadline 30 секунд, 64 активных
execute-запроса на сервер. Ответы и запросы не сжимаются. Эти границы учитывают
base64url overhead для 1 МиБ бакета. Проверка размера идёт и до, и после decrypt.
При превышении размера клиент также прерывает чтение, не аллоцирует неограниченно.
Все ответы с секретами/токенами: `Cache-Control: no-store`; сервер, proxy и APM
не записывают Authorization и тела этих endpoint. HTTPS proxy остаётся доверенным.

## 7. Совместимость и обязательные векторы

Машинно-читаемый [fixture](../tests/fixtures/jwe.json) содержит публичный тестовый токен,
его hash, P-256 JWK, plaintext UTF-8 и JWE с ожидаемым decrypt. Приватный ключ
исключительно тестовый, никогда не используется при развёртывании. Fixture фиксирует
готовый ciphertext; проверка нового encrypt сравнивает расшифрованные байты, а не
случайный ciphertext. Production API не позволяет фиксировать ephemeral key или IV.

Обязательны двусторонний обмен .NET ↔ Go/Python/browser, Unicode/пустые значения,
все негативные проверки профиля, повреждение каждого JWE-сегмента, replay после
restart, подмена replyKey/requestId, неверный audience, границы expiry и лимитов.
Результаты и команды проверок: [verification.md](verification.md).

Дополнительные основания: [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html),
[OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
