## Semgrep

Получаем токен на [semgrep.dev](https://semgrep.dev)

Запускаем сканирование с набором правил `p/java`:

```
docker run --rm -v "${PWD}:/src" -e SEMGREP_APP_TOKEN=<token> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```

```
docker run --rm -v "${PWD}:/src" -e SEMGREP_APP_TOKEN=<тут мой токен ляляля> semgrep/semgrep semgrep scan --config p/java --json --output /src/semgrep-report.json
```
Вариант с кастомным правилом для поиска OpenRedirect:
```
docker run --rm -v "${PWD}:/src" -v "/home/matveysorokin/Desktop/NSU_labs_IS_7-semester/practice/devsecops/spring-rest-unvalidated-redirect.yaml:/rule.yaml" \
-e SEMGREP_APP_TOKEN=<тут мой токен ляляля> semgrep/semgrep semgrep scan --config p/java --config /rule.yaml --json --output /src/semgrep-report-custom.json
```

Он найдет уязвимость path traversal:

```
    @GetMapping("/pathtraversalSemgrep")
    public ResponseEntity<Resource> pathtraversalSemgrep(@RequestParam String filename) {
        Path filePath = Paths.get(UPLOAD_DIR, filename).normalize();
        Resource resource = new FileSystemResource(filePath);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(resource);
    }
```

Но не найдет ее в:

```
    @GetMapping("/pathtraversal")
    public ResponseEntity<Resource> pathtraversal(@RequestParam String filename){
        Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
        Resource resource = new FileSystemResource(filePath);
        return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType(contentType))
                        .body(resource);
    }
```

Потому что [правило](https://github.com/semgrep/semgrep-rules/blob/develop/java/spring/security/injection/tainted-file-path.yaml#L59) ловит паттерн `(Paths $PATHS).get(...)`, в который должен попасть пользовательский ввод - `filename`

## DefectDojo

Запуск:

```
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo  
docker compose up -d
docker compose logs initializer | grep "Admin password:"
```
