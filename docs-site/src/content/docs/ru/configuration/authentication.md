---
title: Аутентификация
description: Настройка аутентификации, OIDC workload identity, API-токенов и контроля доступа в NORA
---


NORA поддерживает несколько методов аутентификации: htpasswd-файлы, OIDC workload identity (для CI/CD систем) и API-токены. Аутентификация отключена по умолчанию и должна быть включена явно.

---

## Включение аутентификации

Установите переменную окружения `NORA_AUTH_ENABLED` или настройте её в `config.toml`:

```bash
# Environment variable
export NORA_AUTH_ENABLED=true
```

```toml
# config.toml
[auth]
enabled = true
htpasswd_file = "users.htpasswd"
token_storage = "data/tokens"
```

---

## Настройка htpasswd

NORA использует Apache-совместимые файлы htpasswd для управления пользователями. Создайте файл паролей с помощью `htpasswd` (из пакета `apache2-utils`) или любого совместимого инструмента:

### Создание файла htpasswd

```bash
# Install htpasswd (Debian/Ubuntu)
apt-get install apache2-utils

# Create file with first user
htpasswd -Bc users.htpasswd admin

# Add additional users
htpasswd -B users.htpasswd developer
htpasswd -B users.htpasswd ci-bot
```

Флаг `-B` использует хеширование bcrypt, что является рекомендуемым алгоритмом.

### Монтирование файла

**Docker:**

```bash
docker run -d \
  --name nora \
  -p 4000:4000 \
  -v /data/nora:/data \
  -v /etc/nora/users.htpasswd:/app/users.htpasswd:ro \
  -e NORA_AUTH_ENABLED=true \
  -e NORA_AUTH_HTPASSWD_FILE=/app/users.htpasswd \
  ghcr.io/getnora-io/nora:latest
```

**Kubernetes:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: nora-htpasswd
type: Opaque
stringData:
  users.htpasswd: |
    admin:$2y$05$...
    ci-bot:$2y$05$...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nora
spec:
  template:
    spec:
      containers:
        - name: nora
          env:
            - name: NORA_AUTH_ENABLED
              value: "true"
            - name: NORA_AUTH_HTPASSWD_FILE
              value: /etc/nora/users.htpasswd
          volumeMounts:
            - name: htpasswd
              mountPath: /etc/nora
              readOnly: true
      volumes:
        - name: htpasswd
          secret:
            secretName: nora-htpasswd
```

---

## Режим анонимного чтения

Когда `NORA_AUTH_ANONYMOUS_READ=true`, неаутентифицированные пользователи могут скачивать артефакты (pull), но аутентификация по-прежнему требуется для операций загрузки (push).

```bash
export NORA_AUTH_ENABLED=true
export NORA_AUTH_ANONYMOUS_READ=true
```

```toml
# config.toml
[auth]
enabled = true
anonymous_read = true
```

Это полезно для организаций, которые хотят обеспечить открытый доступ на чтение (например, для общих библиотек), ограничивая при этом круг лиц, имеющих право публиковать артефакты.

| Операция | Анонимное чтение = false | Анонимное чтение = true |
|-----------|----------------------|----------------------|
| Pull / Скачивание | Требуется аутентификация | Аутентификация не нужна |
| Push / Загрузка | Требуется аутентификация | Требуется аутентификация |
| Удаление / Администрирование | Требуется аутентификация | Требуется аутентификация |

---

## OIDC Workload Identity

NORA поддерживает OIDC (OpenID Connect) workload identity для CI/CD систем -- GitHub Actions и GitLab CI. Пайплайны аутентифицируются без хранения долгоживущих секретов: CI-платформа выдаёт короткоживущий JWT-токен, который NORA валидирует напрямую.

### Как это работает

1. CI-платформа (GitHub Actions, GitLab CI) выдаёт короткоживущий OIDC-токен с claims, идентифицирующими workflow, репозиторий и ветку.
2. Пайплайн отправляет токен как `Bearer`-заголовок в NORA.
3. NORA проверяет подпись JWT по JWKS-эндпоинту провайдера, валидирует issuer, audience и время жизни, затем сопоставляет `sub` claim с ролью по настроенным правилам.

Статические секреты не хранятся в CI -- нужно только настроить audience.

### Конфигурация

```toml
# config.toml
[auth]
enabled = true

[auth.oidc]
enabled = true
leeway_secs = 60          # Допуск расхождения часов (по умолчанию: 60)
jwks_cache_secs = 3600    # TTL кеша JWKS-ключей (по умолчанию: 3600)

[[auth.oidc.providers]]
name = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
audience = "nora"
algorithms = ["RS256", "ES256"]
max_token_lifetime_secs = 900
enabled = true

# Ограничить издателя префиксом namespace (по умолчанию ["*"] = без ограничений).
# Посегментные glob: myorg/* = прямые потомки, myorg/** = любая глубина.
namespace_scope = ["myorg/**"]
# "enforce" (по умолчанию, 403 при выходе за scope) или "audit" (только лог + счётчик).
namespace_scope_enforcement = "enforce"

# Правила ролей: первое совпадение побеждает. Glob-паттерны по `sub` claim.
[[auth.oidc.providers.role_rules]]
pattern = "repo:myorg/*:ref:refs/heads/main"
role = "write"

[[auth.oidc.providers.role_rules]]
pattern = "repo:myorg/*"
role = "read"
```

Переменная окружения:

```bash
export NORA_AUTH_OIDC_ENABLED=true
```

### Ограничение по namespace

`namespace_scope` ограничивает, в какие namespace токены издателя могут **писать**. Применяется к публикации и удалению (PUT/POST/DELETE) для реестров docker, raw, npm, maven, pypi и cargo. Чтение никогда не ограничивается; scope действует только для OIDC-идентичностей (не для API-токенов и не для Basic auth).

Scope сверяется с **координатой** артефакта (а не с URL-путём), посегментно:

| Реестр | Сверяемая координата | Пример scope |
|--------|----------------------|--------------|
| docker | имя образа (`myorg/app`)            | `myorg/**` |
| raw    | путь объекта (`myorg/sub/file`)     | `myorg/**` |
| npm    | пакет со scope (`@myorg/pkg`)       | `@myorg/**` |
| maven  | groupId/artifactId (`com/myorg/lib`)| `com/myorg/**` |
| pypi   | нормализованное имя проекта (`myproj`) | `myproj` |
| cargo  | имя крейта (`mycrate`)              | `mycrate` |

Сопоставление привязано к границам `/`: `*` соответствует ровно одному сегменту, `**` — нулю или более. Поэтому `myorg/*` совпадает с `myorg/app`, но **не** с `myorg-evil/app` и **не** с `myorg/team/app` — для вложенных путей используйте `myorg/**`. Значение по умолчанию `["*"]` отключает ограничение; пустой список `[]` запрещает любую запись (намеренная блокировка). У pypi и cargo плоское пространство имён (без `/`) — ограничивайте по точному имени или используйте `**`.

Запись вне scope возвращает `403 Forbidden`.

> **Замечание об обновлении:** до этого релиза `namespace_scope` принимался, но не применялся. Если вы уже задали значение, отличное от `["*"]`, эта версия начнёт возвращать 403 для записи вне scope — проверьте конфигурацию перед обновлением. Для поэтапного внедрения задайте `namespace_scope_enforcement = "audit"`: запись вне scope разрешается, но логируется и считается метрикой `nora_auth_namespace_scope_total{provider,decision="would_deny"}`. Верните `"enforce"`, когда метрика будет чистой.

### Настройка GitHub Actions

1. Настройте NORA с GitHub OIDC issuer (как показано выше).
2. Добавьте `id-token: write` в permissions workflow.
3. Используйте токен напрямую -- секреты не нужны.

```yaml
name: Publish to NORA
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Get OIDC Token
        id: oidc
        run: |
          TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=nora" | jq -r '.value')
          echo "::add-mask::$TOKEN"
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: Push to NORA
        run: |
          # Docker
          echo "${{ steps.oidc.outputs.token }}" | \
            docker login registry.example.com -u oidc --password-stdin
          docker push registry.example.com/myapp:${{ github.sha }}

          # Или npm
          echo "//registry.example.com/:_authToken=${{ steps.oidc.outputs.token }}" > .npmrc
          npm publish
```

### Настройка GitLab CI

```toml
# config.toml
[[auth.oidc.providers]]
name = "gitlab-ci"
issuer = "https://gitlab.com"   # или URL вашего self-hosted GitLab
audience = "nora"
algorithms = ["RS256"]
max_token_lifetime_secs = 300
enabled = true

[[auth.oidc.providers.role_rules]]
pattern = "project_path:mygroup/*:ref_type:branch:ref:main"
role = "write"

[[auth.oidc.providers.role_rules]]
pattern = "project_path:mygroup/*"
role = "read"
```

```yaml
# .gitlab-ci.yml
publish:
  image: docker:latest
  id_tokens:
    NORA_TOKEN:
      aud: nora
  script:
    - echo "$NORA_TOKEN" | docker login $NORA_REGISTRY -u oidc --password-stdin
    - docker push $NORA_REGISTRY/myapp:$CI_COMMIT_SHA
```

### Правила ролей

Правила ролей используют glob-паттерны, которые сопоставляются с `sub` claim JWT. Побеждает первое совпадение.

| Паттерн | Совпадает с |
|---------|---------|
| `repo:myorg/*:ref:refs/heads/main` | Любой репо в myorg, только ветка main |
| `repo:myorg/*` | Любой репо в myorg, любая ветка |
| `repo:myorg/app:*` | Конкретный репо, любой ref |
| `*` | Всё (catch-all) |

Доступные роли: `read`, `write`, `admin`.

### Свойства безопасности

- **Whitelist алгоритмов**: Только RS256 и ES256 по умолчанию. Симметричные алгоритмы (HS256/HS384/HS512) всегда отклоняются.
- **Строгая привязка issuer**: NORA никогда не следует заголовкам `jku`/`x5u` из токена. Ключи всегда загружаются с настроенного URL issuer.
- **Потолок времени жизни**: Токены с `exp - iat`, превышающим `max_token_lifetime_secs`, отклоняются, даже если ещё не истекли.
- **Stale JWKS fallback**: Если обновление JWKS не удалось (сетевая проблема), NORA продолжает использовать кешированные ключи.
- **Kill switch провайдера**: Отключите провайдера мгновенно через `enabled = false` без удаления конфигурации.

### Несколько провайдеров

Можно настроить несколько OIDC-провайдеров одновременно:

```toml
[[auth.oidc.providers]]
name = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
audience = "nora"
# ...

[[auth.oidc.providers]]
name = "gitlab-ci"
issuer = "https://gitlab.example.com"
audience = "nora"
# ...
```

NORA маршрутизирует каждый токен к правильному провайдеру на основе `iss` claim.

---

## API-токены

API-токены обеспечивают программный доступ без раскрытия учётных данных htpasswd. Токены имеют префикс `nra_` для удобной идентификации и используют хеширование Argon2.

### Роли токенов

| Роль | Разрешения |
|------|------------|
| `read` | Только скачивание артефактов |
| `write` | Скачивание, публикация и загрузка артефактов |
| `admin` | Полный доступ, включая управление токенами |

### Создание токена

```bash
curl -X POST http://localhost:4000/api/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password",
    "role": "write",
    "ttl_days": 90,
    "description": "CI/CD pipeline token"
  }'
```

Ответ:

```json
{
  "token": "nra_a1b2c3d4e5f6...",
  "expires_in_days": 90
}
```

Сохраните значение токена немедленно -- оно показывается только один раз при создании.

### Просмотр списка токенов

```bash
curl -X POST http://localhost:4000/api/tokens/list \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Ответ:

```json
{
  "tokens": [
    {
      "hash_prefix": "a1b2c3",
      "created_at": 1714200000,
      "expires_at": 1721976000,
      "last_used": 1714300000,
      "description": "CI/CD pipeline token",
      "role": "write"
    }
  ]
}
```

### Отзыв токена

Используйте `hash_prefix` из ответа на запрос списка:

```bash
curl -X POST http://localhost:4000/api/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password",
    "hash_prefix": "a1b2c3"
  }'
```

---

## Вход в Docker

NORA поддерживает стандартную аутентификацию Docker. Когда аутентификация включена, используйте `docker login` перед операциями push/pull:

```bash
# Login with htpasswd credentials
docker login localhost:4000
# Username: admin
# Password: ****

# Login with API token (use token as password, any username)
docker login localhost:4000 -u token -p nra_a1b2c3d4e5f6...
```

Для автоматизированных процессов используйте `--password-stdin`:

```bash
echo "nra_a1b2c3d4e5f6..." | docker login localhost:4000 -u token --password-stdin
```

---

## Интеграция с CI/CD

### GitHub Actions

```yaml
name: Build and Push
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Login to NORA
        run: |
          echo "${{ secrets.NORA_TOKEN }}" | \
            docker login registry.example.com -u token --password-stdin

      - name: Build and Push
        run: |
          docker build -t registry.example.com/myapp:${{ github.sha }} .
          docker push registry.example.com/myapp:${{ github.sha }}
```

Для реестров, отличных от Docker (npm, PyPI, Cargo и др.), используйте токен в соответствующей конфигурации клиента:

```yaml
      # npm
      - name: Publish npm package
        env:
          NORA_TOKEN: ${{ secrets.NORA_TOKEN }}
        run: |
          echo "//registry.example.com/:_authToken=${NORA_TOKEN}" > .npmrc
          npm publish --registry=https://registry.example.com

      # PyPI (twine)
      - name: Publish Python package
        env:
          NORA_TOKEN: ${{ secrets.NORA_TOKEN }}
        run: |
          twine upload --repository-url https://registry.example.com/pypi/ \
            -u token -p "${NORA_TOKEN}" dist/*
```

### GitLab CI

```yaml
stages:
  - build
  - publish

variables:
  NORA_REGISTRY: registry.example.com

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - echo "$NORA_TOKEN" | docker login $NORA_REGISTRY -u token --password-stdin
  script:
    - docker build -t $NORA_REGISTRY/myapp:$CI_COMMIT_SHA .
    - docker push $NORA_REGISTRY/myapp:$CI_COMMIT_SHA

publish-maven:
  stage: publish
  image: maven:3.9
  script:
    - >
      mvn deploy
      -DaltDeploymentRepository=nora::https://${NORA_REGISTRY}/maven2
      -Dserver.username=token
      -Dserver.password=${NORA_TOKEN}
```

Сохраните `NORA_TOKEN` как маскированную CI/CD-переменную в настройках проекта GitLab.

---

## Лучшие практики безопасности токенов

1. **Используйте токены с ограниченными правами.** Создавайте токены `read` для рабочих нагрузок, которым нужен только pull, и токены `write` только для пайплайнов, публикующих артефакты.
2. **Устанавливайте TTL.** Всегда указывайте `ttl_days` при создании токенов. Регулярно выполняйте ротацию токенов.
3. **Не коммитьте токены.** Используйте секреты CI/CD (GitHub Secrets, GitLab CI Variables) для передачи токенов во время выполнения.
4. **Отзывайте при компрометации.** Если токен утёк, немедленно отзовите его через API.
5. **Используйте анонимное чтение, когда возможно.** Если ваши артефакты не являются конфиденциальными, включите `NORA_AUTH_ANONYMOUS_READ=true` для снижения нагрузки по управлению токенами.

---

## Смотрите также

- [Справочник по конфигурации](/ru/configuration/settings/) -- все переменные окружения
- [Курирование](/ru/configuration/curation/) -- контроль доступа к пакетам
- [Развёртывание в продакшене](/ru/deployment/production/) -- настройка TLS и прокси
