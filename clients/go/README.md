# DarkVault Go SDK

Самостоятельный клиент для Go 1.25+: HTTPS, JWE, бакеты, секреты и информация о токене.
Модуль не зависит от CLI, Cobra или серверного проекта.

После публикации версии:

```sh
go get github.com/Bobsans/DarkVault/clients/go@v1.0.0
```

```go
package config

import (
    "context"
    "os"

    darkvault "github.com/Bobsans/DarkVault/clients/go"
)

func loadSecrets(ctx context.Context) (map[string]string, error) {
    client, err := darkvault.New("https://vault.example.com", os.Getenv("DARKVAULT_TOKEN"))
    if err != nil {
        return nil, err
    }
    return client.ReadBucket(ctx, "app_qa")
}
```

## API

- Бакеты: `AddBucket`, `GetBucket`, `ListBuckets`, `ReadBucket`,
  `ReadBucketSnapshot`, `UpdateBucket`, `DeleteBucket`.
- Секреты: `AddSecret`, `ReadSecret`, `ListSecrets`, `UpdateSecret`, `SetSecret`, `DeleteSecret`.
- Токен: `GetTokenInfo`.
- Низкоуровневый вызов: `Execute(ctx, operation, parameters)` возвращает `json.RawMessage`.

Все методы принимают `context.Context`. Изменение и удаление требуют актуальную
`Revision`; `SetSecret` с revision `0` создаёт отсутствующий секрет.
Параметр `bucket` — точное имя бакета, а не его UUID.
`ReadBucket` возвращает значения, `ReadBucketSnapshot` — также ID и revision бакета.
Списки возвращают `Page[T]`: передайте пустой cursor для первой страницы, limit от 1 до 200,
затем `*page.NextCursor` для следующей; `nil` означает конец списка.

Серверные ошибки доступны через `errors.As(err, &apiError)` для `*darkvault.APIError`:
`Code`, `Status`, `RequestID`. Текст ошибки не содержит значений секретов.

## Транспорт

`New` проверяет HTTPS origin и формат токена. TLS проверяется системным хранилищем
доверия; редиректы запрещены, в том числе при замене `client.HTTP`.
Для своего CA настройте `http.Transport.TLSClientConfig.RootCAs`, не отключайте проверку TLS.
Настраивайте `client.HTTP` до начала использования; не изменяйте поля клиента во время запросов.

Discovery и запрос используют общий deadline: максимум 30 секунд либо меньший
`client.HTTP.Timeout` или deadline контекста. Каждый вызов получает текущий ключ сервера.
Автоматических повторов нет: при сетевой ошибке записи результат может быть неизвестен;
проверьте состояние перед повтором. SDK не читает конфиг CLI и не сохраняет токен на диск.

## Разработка и релизы

```sh
go test ./...
go vet ./...
```

Для интеграционного теста задайте `DARKVAULT_ACCEPTANCE` путём к descriptor тестового
HTTPS-сервера. Корневой `tools/verify.ps1` запускает этот сервер и тесты SDK и CLI.
`testdata/jwe.json` — публичный fixture; проверка сравнивает его с `tests/fixtures/jwe.json`.

CLI использует локальный `replace` на этот модуль, поэтому изменения протокола общие.
Релизная job прикладывает архив исходников Go SDK и создаёт тег `clients/go/vX.Y.Z`
на том же коммите, что и основной релиз `vX.Y.Z`. Этот префикс нужен Go для модуля
в подпапке. До первого релиза установите SDK из локального checkout через `replace`.
