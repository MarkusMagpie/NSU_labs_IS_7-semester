# Отчет о ДЗ. Поиск уязвимостей с помощью SAST-сканера

## 1. Описание внедренной уязвимости

**Ссылка на отчет о ДЗ 1**: https://github.com/MarkusMagpie/NSU_labs_IS_7-semester/blob/homework1/practice/practice1/demo/OPEN_REDIRECT.md

- **Тип уязвимости:** Open Redirect
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Файл и строки:** `practice/practice1/demo/demoapplication/src/main/java/nsu/security/demoapplication/controller/OrderController.java`, строки 57-63 (уязвимая версия), 71-81 (исправленная версия)

- **Источник (откуда приходят недоверенные данные):** параметр `url` из `@RequestParam String url`
- **Синк (где данные используются опасно):** `.location(URI.create(url))` внутри `ResponseEntity.status(HttpStatus.FOUND)...build()`

Фрагмент уязвимого кода:

```java
@GetMapping("/orders/redirect")
public ResponseEntity<Void> redirectUnsafe(@RequestParam String url) {
    return ResponseEntity
            .status(HttpStatus.FOUND) // установить статус ответа 302
            .location(URI.create(url)) // куда перенаправить
            .build(); // собрать ответ без тела
}
```

Исправление - редирект разрешен только на заранее известный список путей:
```java
// исправление: редирект только на заранее известный список путей
Set<String> ALLOWED_REDIRECT_PATHS = Set.of(
        "/health",
        "/swagger-ui/index.html"
);

@GetMapping("/orders/redirect/safe")
public ResponseEntity<Void> redirectSafe(@RequestParam String url) {
    if (!ALLOWED_REDIRECT_PATHS.contains(url)) {
        return ResponseEntity.badRequest().build();
    }

    return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create(url))
            .build();
}
```

## 2. Параметры запуска

| Параметр | Значение |
| --- | --- |
| Сканер | semgrep |
| Наборы правил | `p/java` |

Команда запуска (из директории `practice/practice1/demo`):
```bash
docker run --rm -v "${PWD}:/src" -e SEMGREP_APP_TOKEN=<token> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```

Проверка покрытия: `OrderController.java` присутствует среди 7 просканированных файлов (`paths.scanned`), ошибок парсинга нет (`errors: []`).

Команда воспроизводима без авторизации (бесплатный набор — 60 Java-правил). Дополнительно прогнано с собственным токеном (`semgrep login`) и полным реестром `p/java` — результат по этой уязвимости идентичен (0 находок), найдена только одна несвязанная находка — хардкод секрета в `OrderJdbcRepository.java:32` (`drivermanager-hardcoded-secret`), не относящаяся к Open Redirect.

Приложенные отчеты сканера:
- без авторизации, 60 правил: [`semgrep-report-open-redirect-baseline-free.json`](semgrep-report-open-redirect-baseline-free.json)
- с авторизацией (с токеном), полный набор правил `p/java`: [`semgrep-report-open-redirect-baseline-full.json`](semgrep-report-open-redirect-baseline-full.json)

## 3. Результаты сканирования

| Версия | Результат | Правило |
| --- | --- | --- |
| Уязвимая | FN | `—` |
| Исправленная | - (находки изначально нет) | `—` |

### 3.1. Уязвимая версия
Находки нет ни с авторизацией, ни без.

Обоснование классификации: **FN**, потому что в коде реально присутствует эксплуатируемый Open Redirect, а сканер его не обнаружил ни с одним из наборов правил `p/java`.

### 3.2. Исправленная версия

Находки нет, исправлять нечего. Сканер и так ничего не нашёл в уязвимой версии.

## 4. Анализ результатов

### 4.2. Почему уязвимость не найдена (для FN)

- **Правило, которое должно было покрыть уязвимость:** [`spring-unvalidated-redirect`](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/audit/spring-unvalidated-redirect.yaml) - единственное правило под Open Redirect для Java/Spring в semgrep-rules
- **Причина расхождения:** синк не входит в правило (правило построено под другую идиому того же фреймворка)
- **Подробное объяснение:** правило `spring-unvalidated-redirect` ищет 4 паттерна:
  ```yaml
  pattern-either:
  - pattern: |
      $X $METHOD(...,String $URL,...) {
        return "redirect:" + $URL;
      }
  - pattern: |
      $X $METHOD(...,String $URL,...) {
        ...
        String $REDIR = "redirect:" + $URL;
        ...
        return $REDIR;
        ...
      }
  - pattern: |
      $X $METHOD(...,String $URL,...) {
        ...
        new ModelAndView("redirect:" + $URL);
        ...
      }
  - pattern: |-
      $X $METHOD(...,String $URL,...) {
        ...
        String $REDIR = "redirect:" + $URL;
        ...
        new ModelAndView($REDIR);
        ...
      }
  ```
  Мой код использует другой синк - `ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build()`. Он никогда не строит строку с префиксом `"redirect:"` и не обращается к `ModelAndView`, поэтому структурно не совпадает ни с одним из 4 паттернов правила.

  отчет: [`semgrep-report-open-redirect-official-rule.json`](semgrep-report-open-redirect-official-rule.json)

## 5. Доработка (если подходящего правила нет)

Выбранный вариант: **А**

### Вариант А. Собственное правило

Файл правила: [`spring-rest-unvalidated-redirect.yaml`](spring-rest-unvalidated-redirect.yaml):
```yaml
rules:
- id: spring-rest-unvalidated-redirect
  languages: [java]
  severity: WARNING
  message: >-
    Application redirects a user to a destination URL taken from a user-supplied parameter via
    ResponseEntity.location(URI.create(...)), without validating it against an allow-list.
  metadata:
    cwe:
    - "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
    category: security
    technology: [spring]
  pattern: |
    ResponseEntity.status($S).location(URI.create($URL)).build()
```

Логика правила: вызов цепочки `ResponseEntity.status($S).location(URI.create($URL)).build()` целиком (новый синк).

Команда запуска:
```bash
docker run --rm -v "${PWD}:/src" -v "$(pwd)/practice/devsecops/spring-rest-unvalidated-redirect.yaml:/rule.yaml" semgrep/semgrep semgrep scan --config /rule.yaml --json --output /src/semgrep-report.json
```
Команда запуска 2 (мое правило + набор правил p/java):
```bash
docker run --rm -v "${PWD}:/src" -v "/home/matveysorokin/Desktop/NSU_labs_IS_7-semester/practice/devsecops/spring-rest-unvalidated-redirect.yaml:/rule.yaml" \
-e SEMGREP_APP_TOKEN=<тут мой токен ляляля> semgrep/semgrep semgrep scan --config p/java --config /rule.yaml --json --output /src/semgrep-report-custom.json
```

Результаты запуска правила:
| Версия | Результат | Комментарий |
| --- | --- | --- |
| Уязвимая | TP | Найдено на строках 59-62 `OrderController.java`, тот же CWE-601, то же место реальной уязвимости |
| Исправленная | FP | Найдено на строках 77-80, хотя код защищен проверкой `ALLOWED_REDIRECT_PATHS.contains(url)` на 73 строке |

Отчёт: [`semgrep-report-open-redirect-custom-rule.json`](semgrep-report-open-redirect-custom-rule.json)

Сообщение сканера (одинаковое для обеих находок): "Application redirects a user to a destination URL taken from a user-supplied parameter via ResponseEntity.location(URI.create(...)), without validating it against an allow-list."

Почему исправленная версия тоже даёт срабатывание (FP): правило чисто синтаксическое и матчит только финальный вызов `.location(URI.create($URL))`. Правило не анализирует поток данных до этой точки, не видит что строкой выше (73) уже стоит проверка `if (!ALLOWED_REDIRECT_PATHS.contains(url)) return ResponseEntity.badRequest().build();`. Для устранения этого FP правилу нужен учет предшествующей валидации.

## 6. Выводы
Официальный реестр semgrep-rules покрывает Open Redirect для Spring только через `"redirect:" + url` / `ModelAndView`, но не через REST api `ResponseEntity.location(URI.create(url))` который используется в моем коде -> отсюда FN (проверил и с бесплатным, и с полным `p/java). Написанное правило закрывает именно этот синк и находит реальную уязвимость, но будучи чисто синтаксическим не различает защищенную и незащищенную версии кода (FP на исправленной версии показывал выше). 

Практический вывод: для REST-контроллеров на Spring стандартные правила SAST-сканера sempreg (p/java) могут давать ложное чувство безопасности; стоит либо дополнять набор правил кастомными правилами под используемые в проекте паттерны, либо явно проверять покрытие используемых API в выбранном статическом сканнере перед тем, как доверять его отчету.
