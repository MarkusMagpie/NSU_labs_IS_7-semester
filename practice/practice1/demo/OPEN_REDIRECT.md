# ДЗ 1. Уязвимость: Open Redirect

## Суть уязвимости
Open Redirect  сервер доверяет пользователю в выборе адреса, куда его перенаправить, и никак этот самый адрес не проверяет. 

Код добавлен в `demoapplication/src/main/java/nsu/security/demoapplication/controller/OrderController.java`.

## Уязвимый код
```java
@GetMapping("/orders/redirect")
public ResponseEntity<Void> redirectUnsafe(@RequestParam String url) {
    return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(url))
            .build();
}
```

Разбор:
- `@GetMapping("/orders/redirect")` - метод обрабатывает GET-запросы на путь `/orders/redirect`
- `@RequestParam String url` - значение параметра `url` из адресной строки которую дает пользователь (то что после `?url=...`) забирается без проверки
- `ResponseEntity.status(HttpStatus.FOUND)` - устанавливает код ответа 302
- `.location(URI.create(url))` - кладет переданный пользователем адрес в заголовок ответа `Location`
- `.build()` — собирает финальный HTTP-ответ

Логика: пользователь отправляет запрос на `/orders/redirect?url=...` -> 
сервер отвечает `302` с заголовком `Location`, равным переданному один в один `url` и браузер автоматически переходит по этому адресу.

## PoC (Proof of Concept)

### Уязвимый эндпоинт. пример редиректа на посторонний сайт
Запрос:
```bash
curl -i 'http://localhost:8080/orders/redirect?url=https://example.com'
```

Ответ:
```
HTTP/1.1 302
Location: https://example.com
Content-Length: 0
Date: Fri, 11 Sep 2026 15:32:34 GMT
```

Сервер поставил в `Location` переданный извне адрес. при открытии такой ссылки в браузере происходит переход на `example.com`, хотя изначальная ссылка вела на `localhost:8080`.

### Тот же сценарий через безопасный эндпоинт (после вышеописанного исправления)
Запрос:
```bash
curl -i 'http://localhost:8080/orders/redirect/safe?url=https://example.com'
```

Ответ:
```
HTTP/1.1 400
Content-Length: 0
Date: Fri, 11 Sep 2026 15:33:45 GMT
Connection: close
```
Редирект на посторонний адрес ОТКЛОНЕН с кодом 400

### Безопасный эндпоинт. Разрешённые пути работают (из белого списка)
Запрос:
```bash
curl -i 'http://localhost:8080/orders/redirect/safe?url=/health'
```

Ответ:
```
HTTP/1.1 302
Location: /health
Content-Length: 0
Date: Fri, 11 Sep 2026 15:35:25 GMT
```

Редирект на путь из белого списка выполняется как обычно без каких-либо проблем.

## Исправление

```java
private static final Set<String> ALLOWED_REDIRECT_PATHS = Set.of(
        "/health",
        "/swagger-ui/index.html"
);

@GetMapping("/orders/redirect/safe")
public ResponseEntity<Void> redirectSafe(@RequestParam String url) {
    if (!ALLOWED_REDIRECT_PATHS.contains(url)) {
        return ResponseEntity.badRequest().build();
    }

    return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create(url))
            .build();
}
```

Суть фикса - не позволять клиенту задавать адрес самому. Вместо этого заранее на стороне сервера определён список разрешённых адресов `ALLOWED_REDIRECT_PATHS`. 
Прежде чем редиректить метод проверяет, есть ли переданный `url` в этом списке:
- если адреса нет в списке то возвращается `400 Bad Request`, редирект не
  выполняется;
- если адрес есть в списке то выполняется тот же самый редирект, что и в
  уязвимой версии.

Т.е. сервер сам решает куда можно перенаправлять пользователя, а не полагается как раньше на присланное клиентом значение.

## Как воспроизвести локально
1. Запустить приложение: `docker compose up --build -d` (из папки `demo/`).
2. Выполнить вышеопсианные запросы через `curl` либо (2 вариант) открыть уязвимую ссылку в
   браузере: `http://localhost:8080/orders/redirect?url=https://example.com`.
