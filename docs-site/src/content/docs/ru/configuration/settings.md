---
title: Справочник по конфигурации
description: Полный справочник по всем параметрам конфигурации NORA
---


NORA использует многоуровневую модель конфигурации с тремя уровнями приоритета:

1. **Переменные окружения** (наивысший приоритет)
2. **Файл config.toml**
3. **Встроенные значения по умолчанию** (наименьший приоритет)

Порядок поиска конфигурационного файла:
- Переменная окружения `NORA_CONFIG_PATH` (критическая ошибка, если задана, но файл не найден)
- `config.toml` в текущей рабочей директории (необязательно)
- Встроенные значения по умолчанию, если файл не найден

---

## Переменные окружения

### Сервер

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_HOST` | `127.0.0.1` | Адрес привязки |
| `NORA_PORT` | `4000` | Порт прослушивания |
| `NORA_PUBLIC_URL` | *(нет)* | Публичный URL для генерируемых ссылок на скачивание (например, `https://registry.example.com`). **Обязателен** при `NORA_HOST=0.0.0.0` или при работе за reverse proxy, иначе клиенты получат недоступные URL в ответах Cargo, PyPI, npm, NuGet и Terraform. |
| `NORA_BODY_LIMIT_MB` | `2048` | Максимальный размер тела запроса в МБ |
| `NORA_CONFIG_PATH` | *(нет)* | Путь к файлу config.toml |

### Хранилище

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_STORAGE_MODE` | `local` | Бэкенд хранилища: `local` или `s3` |
| `NORA_STORAGE_PATH` | `data/storage` | Директория локального хранилища |
| `NORA_STORAGE_S3_URL` | `http://127.0.0.1:9000` | URL S3-совместимого эндпоинта |
| `NORA_STORAGE_BUCKET` | `registry` | Имя бакета S3 |
| `NORA_STORAGE_S3_ACCESS_KEY` | *(нет)* | Ключ доступа S3 |
| `NORA_STORAGE_S3_SECRET_KEY` | *(нет)* | Секретный ключ S3 |
| `NORA_STORAGE_S3_REGION` | `us-east-1` | Регион S3 |

### Аутентификация

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_AUTH_ENABLED` | `false` | Включить аутентификацию |
| `NORA_AUTH_ANONYMOUS_READ` | `false` | Разрешить неаутентифицированный доступ на чтение (pull) |
| `NORA_AUTH_HTPASSWD_FILE` | `users.htpasswd` | Путь к файлу htpasswd |
| `NORA_AUTH_TOKEN_STORAGE` | `data/tokens` | Директория для хранения API-токенов |

### Включение/отключение реестров

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_DOCKER_ENABLED` | `true` | Включить реестр Docker (OCI) |
| `NORA_MAVEN_ENABLED` | `true` | Включить реестр Maven |
| `NORA_NPM_ENABLED` | `true` | Включить реестр npm |
| `NORA_CARGO_ENABLED` | `true` | Включить реестр Cargo (Rust) |
| `NORA_PYPI_ENABLED` | `true` | Включить реестр PyPI (Python) |
| `NORA_GO_ENABLED` | `true` | Включить прокси модулей Go |
| `NORA_RAW_ENABLED` | `true` | Включить хранилище необработанных файлов |
| `NORA_GEMS_ENABLED` | `false` | Включить реестр RubyGems |
| `NORA_TF_ENABLED` | `false` | Включить реестр провайдеров Terraform |
| `NORA_ANSIBLE_ENABLED` | `false` | Включить реестр Ansible Galaxy |
| `NORA_NUGET_ENABLED` | `false` | Включить реестр NuGet |
| `NORA_PUB_ENABLED` | `false` | Включить реестр Dart/Flutter pub |
| `NORA_CONAN_ENABLED` | `false` | Включить реестр Conan (C/C++) |

### Maven

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_MAVEN_PROXIES` | `https://repo1.maven.org/maven2` | Вышестоящие прокси. Формат: `url1,url2` или `url1\|auth1,url2\|auth2` |
| `NORA_MAVEN_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_MAVEN_CHECKSUM_VERIFY` | `true` | Проверять загруженные контрольные суммы по вычисленным на сервере значениям |
| `NORA_MAVEN_IMMUTABLE_RELEASES` | `true` | Запретить перезапись выпущенных (не-SNAPSHOT) артефактов |

### npm

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_NPM_PROXY` | `https://registry.npmjs.org` | Вышестоящий реестр npm |
| `NORA_NPM_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_NPM_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_NPM_METADATA_TTL` | `300` | TTL кэша метаданных в секундах (0 = кэшировать навсегда) |

### PyPI

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_PYPI_PROXY` | `https://pypi.org/simple/` | Вышестоящий реестр PyPI |
| `NORA_PYPI_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_PYPI_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |

### Docker

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_DOCKER_PROXIES` | `https://registry-1.docker.io` | Вышестоящие реестры. Формат: `url1,url2` или `url1\|auth1,url2\|auth2` |
| `NORA_DOCKER_PROXY_TIMEOUT` | `300` | Таймаут прокси в секундах |

### Go

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_GO_PROXY` | `https://proxy.golang.org` | Вышестоящий прокси модулей Go |
| `NORA_GO_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_GO_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_GO_PROXY_TIMEOUT_ZIP` | `120` | Таймаут загрузки .zip в секундах |
| `NORA_GO_MAX_ZIP_SIZE` | `104857600` | Максимальный размер zip-архива модуля в байтах (по умолчанию 100 МБ) |

### Cargo

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_CARGO_PROXY` | `https://crates.io` | Вышестоящий реестр Cargo |
| `NORA_CARGO_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_CARGO_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |

### Raw

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_RAW_MAX_FILE_SIZE` | `104857600` | Максимальный размер файла в байтах (по умолчанию 100 МБ) |
| `NORA_RAW_CACHE_CONTROL` | `no-cache` | Заголовок `Cache-Control` для GET/HEAD ответов |

### RubyGems

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_GEMS_PROXY` | `https://rubygems.org` | Вышестоящий реестр RubyGems |
| `NORA_GEMS_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_GEMS_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_GEMS_METADATA_TTL` | `300` | TTL кэша метаданных compact-index в секундах |

### Terraform

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_TF_PROXY` | `https://registry.terraform.io` | Вышестоящий реестр Terraform |
| `NORA_TF_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_TF_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_TF_PROXY_TIMEOUT_DL` | `120` | Таймаут загрузки бинарных файлов в секундах |

### Ansible Galaxy

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_ANSIBLE_PROXY` | `https://galaxy.ansible.com` | Вышестоящий сервер Galaxy |
| `NORA_ANSIBLE_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_ANSIBLE_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |

### NuGet

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_NUGET_PROXY` | `https://api.nuget.org` | Вышестоящий API NuGet |
| `NORA_NUGET_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_NUGET_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_NUGET_METADATA_TTL` | `300` | TTL кэша метаданных в секундах |

### Pub (Dart/Flutter)

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_PUB_PROXY` | `https://pub.dev` | Вышестоящий реестр pub |
| `NORA_PUB_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_PUB_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |

### Conan (C/C++)

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_CONAN_PROXY` | `https://center2.conan.io` | Вышестоящий реестр Conan |
| `NORA_CONAN_PROXY_AUTH` | *(нет)* | Аутентификация вышестоящего реестра (`user:pass`) |
| `NORA_CONAN_PROXY_TIMEOUT` | `30` | Таймаут прокси в секундах |
| `NORA_CONAN_PROXY_TIMEOUT_DL` | `120` | Таймаут загрузки бинарных файлов в секундах |
| `NORA_CONAN_METADATA_TTL` | `300` | TTL кэша метаданных в секундах |

### Ограничение частоты запросов

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_RATE_LIMIT_ENABLED` | `true` | Включить ограничение частоты запросов |
| `NORA_RATE_LIMIT_AUTH_RPS` | `1` | Запросов в секунду к эндпоинту аутентификации |
| `NORA_RATE_LIMIT_AUTH_BURST` | `5` | Размер всплеска для эндпоинта аутентификации |
| `NORA_RATE_LIMIT_UPLOAD_RPS` | `200` | Запросов на загрузку в секунду |
| `NORA_RATE_LIMIT_UPLOAD_BURST` | `500` | Размер всплеска для загрузки |
| `NORA_RATE_LIMIT_GENERAL_RPS` | `100` | Общих запросов в секунду |
| `NORA_RATE_LIMIT_GENERAL_BURST` | `200` | Размер всплеска для общих запросов |

### Сборка мусора

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_GC_ENABLED` | `false` | Включить фоновую сборку мусора |
| `NORA_GC_INTERVAL` | `86400` | Интервал между запусками GC в секундах (по умолчанию 24 ч) |
| `NORA_GC_DRY_RUN` | `false` | Только отчёт об orphan-объектах без удаления |

### Политики хранения

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_RETENTION_ENABLED` | `false` | Включить фоновые политики хранения |
| `NORA_RETENTION_INTERVAL` | `86400` | Интервал между запусками в секундах (по умолчанию 24 ч) |
| `NORA_RETENTION_DRY_RUN` | `false` | Только отчёт о том, что будет удалено |

### Курирование

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_CURATION_MODE` | `off` | Режим курирования: `off`, `audit`, `enforce` |
| `NORA_CURATION_ON_FAILURE` | `closed` | Поведение при ошибке фильтра: `closed` (блокировать) или `open` (разрешить) |
| `NORA_CURATION_ALLOWLIST_PATH` | *(нет)* | Путь к JSON-файлу списка разрешений |
| `NORA_CURATION_BLOCKLIST_PATH` | *(нет)* | Путь к JSON-файлу списка блокировки |
| `NORA_CURATION_BYPASS_TOKEN` | *(нет)* | Токен для обхода проверок курирования |
| `NORA_CURATION_REQUIRE_INTEGRITY` | `false` | Требовать метаданные целостности в записях списка разрешений |
| `NORA_CURATION_INTERNAL_NS` | *(нет)* | Разделённые запятой glob-паттерны для внутренних пространств имён |
| `NORA_CURATION_MIN_RELEASE_AGE` | *(нет)* | Глобальный мин. возраст релиза (`7d`, `12h`, `2w`) |
| `NORA_CURATION_NPM_MIN_RELEASE_AGE` | *(нет)* | Мин. возраст релиза для npm |
| `NORA_CURATION_PYPI_MIN_RELEASE_AGE` | *(нет)* | Мин. возраст релиза для PyPI |
| `NORA_CURATION_CARGO_MIN_RELEASE_AGE` | *(нет)* | Мин. возраст релиза для Cargo |
| `NORA_CURATION_GO_MIN_RELEASE_AGE` | *(нет)* | Мин. возраст релиза для Go |
| `NORA_CURATION_DOCKER_MIN_RELEASE_AGE` | *(нет)* | Мин. возраст релиза для Docker |

### Секреты

| Переменная | По умолчанию | Описание |
|----------|---------|-------------|
| `NORA_SECRETS_PROVIDER` | `env` | Провайдер секретов (реализован только `env`) |
| `NORA_SECRETS_CLEAR_ENV` | `false` | Очищать переменные окружения после чтения (провайдер env) |

---

## Справочник config.toml

Ниже приведён полный файл `config.toml` со всеми секциями и значениями по умолчанию.

```toml
# =============================================================================
# Server
# =============================================================================
[server]
host = "127.0.0.1"
port = 4000
# public_url = "https://registry.example.com"  # Обязательно при host = 0.0.0.0 или за reverse proxy
body_limit_mb = 2048

# =============================================================================
# Storage
# =============================================================================
[storage]
mode = "local"          # "local" or "s3"
path = "data/storage"

# S3 settings (used when mode = "s3")
s3_url = "http://127.0.0.1:9000"
bucket = "registry"
# s3_access_key = ""
# s3_secret_key = ""
s3_region = "us-east-1"

# =============================================================================
# Authentication
# =============================================================================
[auth]
enabled = false
anonymous_read = false
htpasswd_file = "users.htpasswd"
token_storage = "data/tokens"

# =============================================================================
# Secrets
# =============================================================================
[secrets]
provider = "env"        # реализован только "env"
clear_env = false

# =============================================================================
# Rate Limiting
# =============================================================================
[rate_limit]
enabled = true
auth_rps = 1
auth_burst = 5
upload_rps = 200
upload_burst = 500
general_rps = 100
general_burst = 200

# =============================================================================
# Docker (OCI) Registry
# =============================================================================
[docker]
enabled = true
proxy_timeout = 60

[[docker.upstreams]]
url = "https://registry-1.docker.io"
# auth = "user:pass"

# =============================================================================
# Maven Registry
# =============================================================================
[maven]
enabled = true
proxy_timeout = 30
checksum_verify = true
immutable_releases = true
proxies = ["https://repo1.maven.org/maven2"]

# Authenticated upstream example:
# [[maven.proxies]]
# url = "https://private.repo.com/maven2"
# auth = "user:pass"

# =============================================================================
# npm Registry
# =============================================================================
[npm]
enabled = true
proxy = "https://registry.npmjs.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300

# =============================================================================
# Cargo (Rust) Registry
# =============================================================================
[cargo]
enabled = true
proxy = "https://crates.io"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# PyPI (Python) Registry
# =============================================================================
[pypi]
enabled = true
proxy = "https://pypi.org/simple/"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# Go Module Proxy
# =============================================================================
[go]
enabled = true
proxy = "https://proxy.golang.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_zip = 120
max_zip_size = 104857600    # 100MB

# =============================================================================
# Raw File Storage
# =============================================================================
[raw]
enabled = true
max_file_size = 104857600   # 100MB
cache_control = "no-cache"

# =============================================================================
# RubyGems Registry
# =============================================================================
[gems]
enabled = false
proxy = "https://rubygems.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300

# =============================================================================
# Terraform Provider Registry
# =============================================================================
[terraform]
enabled = false
proxy = "https://registry.terraform.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_dl = 120

# =============================================================================
# Ansible Galaxy Registry
# =============================================================================
[ansible]
enabled = false
proxy = "https://galaxy.ansible.com"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# NuGet Registry
# =============================================================================
[nuget]
enabled = false
proxy = "https://api.nuget.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300

# =============================================================================
# Dart/Flutter Pub Registry
# =============================================================================
[pub_dart]
enabled = false
proxy = "https://pub.dev"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# Conan (C/C++) Registry
# =============================================================================
[conan]
enabled = false
proxy = "https://center2.conan.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_dl = 120
metadata_ttl = 300

# =============================================================================
# Garbage Collection
# =============================================================================
[gc]
enabled = false
interval = 86400        # 24 hours
dry_run = false

# =============================================================================
# Retention Policies
# =============================================================================
[retention]
enabled = false
interval = 86400        # 24 hours
dry_run = false

# Retention rules: registry = "*" applies to all formats
# [[retention.rules]]
# registry = "docker"
# keep_last = 10
# older_than_days = 90
# exclude_tags = ["latest", "v*"]

# [[retention.rules]]
# registry = "*"
# older_than_days = 180

# =============================================================================
# Curation (Package Access Control)
# =============================================================================
[curation]
mode = "off"                # "off", "audit", "enforce"
on_failure = "closed"       # "closed" (fail-safe) or "open" (fail-open)
# allowlist_path = "/etc/nora/allowlist.json"
# blocklist_path = "/etc/nora/blocklist.json"
# bypass_token = ""         # prefer NORA_CURATION_BYPASS_TOKEN env var
require_integrity = false
internal_namespaces = []    # e.g., ["@mycompany/**", "com.mycompany.**"]
```

---

## Приоритет конфигурации

Когда один и тот же параметр задан в нескольких местах, источник с наивысшим приоритетом имеет преимущество:

```
Переменная окружения  >  config.toml  >  встроенное значение по умолчанию
```

Например, если в `config.toml` задано `port = 8080`, но также установлена переменная `NORA_PORT=4000`, NORA будет слушать порт 4000.

---

## Безопасность учётных данных

NORA выдаёт предупреждение при запуске, если учётные данные (аутентификация прокси, ключи S3) обнаружены в `config.toml` в открытом виде. Рекомендуется передавать учётные данные через переменные окружения или провайдер секретов:

```bash
# Use env vars for credentials
export NORA_STORAGE_S3_ACCESS_KEY="your-key"
export NORA_STORAGE_S3_SECRET_KEY="your-secret"
export NORA_DOCKER_PROXIES="https://registry-1.docker.io|user:pass"
```

В Kubernetes монтируйте учётные данные из Secret в окружение контейнера вместо хранения их в `config.toml`.

---

## Смотрите также

- [Аутентификация](/ru/configuration/authentication/) -- управление пользователями и API-токены
- [Курирование](/ru/configuration/curation/) -- контроль доступа к пакетам
- [Ограничение частоты запросов](/ru/configuration/rate-limits/) -- настройка ограничений
- [Развёртывание в продакшене](/ru/deployment/production/) -- руководство по продакшен-развёртыванию
