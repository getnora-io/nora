# Changelog

## [0.2.34] - 2026-03-20

### Fixed
- **UI**: Group consecutive identical activity entries — repeated cache hits show as "artifact (x4)" instead of 4 identical rows
- **UI**: Fix table cell padding in Mount Points and Activity tables — th/td alignment now consistent
- **Security**: Update tar crate 0.4.44 → 0.4.45 (CVE-2026-33055 PAX size header bypass, CVE-2026-33056 symlink chmod traversal)

### Added
- 82 new unit tests across 7 modules (activity_log, audit, config, dashboard_metrics, error, metrics, repo_index)
- Test coverage badge in README (12.55% → 21.56%)
- Dashboard GIF (EN/RU crossfade) in README
- 7 missing environment variables added to docs (NORA_PUBLIC_URL, S3 credentials, NPM_METADATA_TTL, Raw config)

### Changed
- README restructured: tagline + docker run + GIF first, badges moved to Security section
- Remove hardcoded OpenSSF Scorecard version from README


## [0.2.33] - 2026-03-19

### Security
- Verify blob digest (SHA256) on upload — reject mismatches with DIGEST_INVALID error
- Reject sha512 digests (only sha256 supported for blob uploads)
- Add upload session limits: max 100 concurrent, 2GB per session, 30min TTL (configurable via NORA_MAX_UPLOAD_SESSIONS, NORA_MAX_UPLOAD_SESSION_SIZE_MB)
- Bind upload sessions to repository name (prevent session fixation attacks)
- Add security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Run containers as non-root user (USER nora) in all Dockerfiles

### Fixed
- Filter .meta.json from Docker tag list (fixes ArgoCD Image Updater tag recursion)
- Fix catalog endpoint to show namespaced images correctly (library/alpine instead of library)

### Added
- CodeQL workflow for SAST analysis
- SLSA provenance attestation for release artifacts

### Changed
- Configurable upload session size for ML models via NORA_MAX_UPLOAD_SESSION_SIZE_MB (default 2048 MB)

## [0.2.32] - 2026-03-18

### Fixed / Исправлено
- **Docker dashboard**: Namespaced images (library/alpine, grafana/grafana) now visible in UI — index builder finds manifests by position, not fixed index
- **Docker proxy**: Auto-prepend `library/` for single-segment official Hub images (nginx, alpine, node) — no need to explicitly use library/ prefix
- **CI**: Fixed cargo-deny license checks (NCSA for libfuzzer-sys, MIT for fuzz crate, unused-allowed-license config)
- **Docker dashboard**: Namespaced-образы (library/alpine, grafana/grafana) теперь отображаются в UI
- **Docker proxy**: Автоподстановка `library/` для официальных образов Docker Hub (nginx, alpine, node) — больше не нужно указывать library/ вручную
- **CI**: Исправлены проверки лицензий cargo-deny



## [0.2.31] - 2026-03-16

### Added / Добавлено
- **npm URL rewriting**: Tarball URLs in proxied metadata now rewritten to point to NORA (previously tarballs bypassed NORA and downloaded directly from npmjs.org)
- **npm scoped packages**: Full support for `@scope/package` in proxy handler and repository index
- **npm publish**: `PUT /npm/{package}` accepts standard npm publish payload with base64-encoded tarballs
- **npm metadata TTL**: Configurable cache TTL (`NORA_NPM_METADATA_TTL`, default 300s) with stale-while-revalidate fallback
- **Immutable cache**: SHA256 integrity verification on cached npm tarballs — detects tampering on cache hit
- **npm URL rewriting**: Tarball URL в проксированных метаданных теперь переписываются на NORA (ранее тарболы шли напрямую из npmjs.org)
- **npm scoped packages**: Полная поддержка `@scope/package` в прокси-хендлере и индексе репозитория
- **npm publish**: `PUT /npm/{package}` принимает стандартный npm publish payload с base64-тарболами
- **npm metadata TTL**: Настраиваемый TTL кеша (`NORA_NPM_METADATA_TTL`, default 300s) с stale-while-revalidate
- **Immutable cache**: SHA256 проверка целостности npm-тарболов — обнаружение подмены при отдаче из кеша

### Security / Безопасность
- **Path traversal protection**: Attachment filename validation in npm publish (rejects `../`, `/`, `\`)
- **Package name mismatch**: npm publish rejects payloads where URL path doesn't match `name` field (anti-spoofing)
- **Version immutability**: npm publish returns 409 Conflict on duplicate version
- **Защита от path traversal**: Валидация имён файлов в npm publish (отклоняет `../`, `/`, `\`)
- **Проверка имени пакета**: npm publish отклоняет payload если имя в URL не совпадает с полем `name` (anti-spoofing)
- **Иммутабельность версий**: npm publish возвращает 409 Conflict при попытке перезаписать версию

### Fixed / Исправлено
- **npm proxy_auth**: `proxy_auth` field was configured but not wired into `fetch_from_proxy` — now sends Basic Auth header to upstream
- **npm proxy_auth**: Поле `proxy_auth` было в конфиге, но не передавалось в `fetch_from_proxy` — теперь отправляет Basic Auth в upstream



All notable changes to NORA will be documented in this file.

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.29] - 2026-03-15

### Added / Добавлено
- **Upstream Authentication**: All registry proxies now support Basic Auth credentials for private upstream registries
- **Аутентификация upstream**: Все прокси реестров теперь поддерживают Basic Auth для приватных upstream-реестров
  - Docker: `NORA_DOCKER_UPSTREAMS="https://registry.corp.com|user:pass"`
  - Maven: `NORA_MAVEN_PROXIES="https://nexus.corp.com/maven2|user:pass"`
  - npm: `NORA_NPM_PROXY_AUTH="user:pass"`
  - PyPI: `NORA_PYPI_PROXY_AUTH="user:pass"`
- **Plaintext credential warning**: NORA logs a warning at startup if credentials are stored in config.toml instead of env vars
- **Предупреждение о plaintext credentials**: NORA логирует предупреждение при старте, если credentials хранятся в config.toml вместо переменных окружения

### Changed / Изменено
- Extracted `basic_auth_header()` helper for consistent auth across all protocols
- Вынесен хелпер `basic_auth_header()` для единообразной авторизации всех протоколов

### Removed / Удалено
- Removed unused `DockerAuth::fetch_with_auth()` method (dead code cleanup)
- Удалён неиспользуемый метод `DockerAuth::fetch_with_auth()` (очистка мёртвого кода)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.28] - 2026-03-13

### Fixed / Исправлено
- **docker-compose.yml**: Fixed image reference from `getnora/nora:latest` to `ghcr.io/getnora-io/nora:latest`
- **docker-compose.yml**: Исправлена ссылка на образ с `getnora/nora:latest` на `ghcr.io/getnora-io/nora:latest`

### Documentation / Документация
- **Authentication Guide**: Added complete auth setup guide in README — htpasswd, API tokens, RBAC roles, curl examples
- **Руководство по аутентификации**: Добавлено полное руководство по настройке auth в README — htpasswd, API-токены, RBAC-роли, примеры curl
- **FSTEC builds**: Documented `Dockerfile.astra` and `Dockerfile.redos` purpose in README
- **Сборки ФСТЭК**: Документировано назначение `Dockerfile.astra` и `Dockerfile.redos` в README
- **TLS / HTTPS**: Added reverse proxy setup guide (Caddy, Nginx) and `insecure-registries` Docker config for internal deployments
- **TLS / HTTPS**: Добавлено руководство по настройке reverse proxy (Caddy, Nginx) и конфигурация `insecure-registries` Docker для внутренних инсталляций

### Removed / Удалено
- Removed stale `CHANGELOG.md.bak` from repository
- Удалён устаревший `CHANGELOG.md.bak` из репозитория

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.27] - 2026-03-03

### Added / Добавлено
- **Configurable body limit**: `NORA_BODY_LIMIT_MB` env var (default: `2048` = 2GB) — replaces hardcoded 100MB limit that caused `413 Payload Too Large` on large Docker image push
- **Настраиваемый лимит тела запроса**: переменная `NORA_BODY_LIMIT_MB` (по умолчанию: `2048` = 2GB) — заменяет захардкоженный лимит 100MB, вызывавший `413 Payload Too Large` при push больших Docker-образов
- **Docker Delete API**: `DELETE /v2/{name}/manifests/{reference}` and `DELETE /v2/{name}/blobs/{digest}` per Docker Registry V2 spec (returns 202 Accepted)
- **Docker Delete API**: `DELETE /v2/{name}/manifests/{reference}` и `DELETE /v2/{name}/blobs/{digest}` по спецификации Docker Registry V2 (возвращает 202 Accepted)
- Namespace-qualified DELETE variants (`/v2/{ns}/{name}/...`)
- Audit log integration for delete operations

### Fixed / Исправлено
- Docker push of images >100MB no longer fails with 413 error
- Push Docker-образов >100MB больше не падает с ошибкой 413

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.26] - 2026-03-03

### Added / Добавлено
- **Helm OCI support**: `helm push` / `helm pull` now works out of the box via OCI protocol
- **Поддержка Helm OCI**: `helm push` / `helm pull` теперь работают из коробки через OCI протокол
- **RBAC**: Token-based role system with three roles — `read`, `write`, `admin` (default: `read`)
- **RBAC**: Ролевая система на основе токенов — `read`, `write`, `admin` (по умолчанию: `read`)
- **Audit log**: Persistent append-only JSONL audit trail for all registry operations (`{storage}/audit.jsonl`)
- **Аудит**: Персистентный append-only JSONL лог всех операций реестра (`{storage}/audit.jsonl`)
- **GC command**: `nora gc --dry-run` — garbage collection for orphaned blobs (mark-and-sweep)
- **Команда GC**: `nora gc --dry-run` — сборка мусора для осиротевших блобов (mark-and-sweep)

### Fixed / Исправлено
- **Helm OCI pull**: Fixed OCI manifest media type detection — manifests with non-Docker `config.mediaType` now correctly return `application/vnd.oci.image.manifest.v1+json`
- **Helm OCI pull**: Исправлено определение media type OCI манифестов — манифесты с не-Docker `config.mediaType` теперь корректно возвращают `application/vnd.oci.image.manifest.v1+json`
- **Docker-Content-Digest**: Added missing header in blob upload response (required by Helm OCI client)
- **Docker-Content-Digest**: Добавлен отсутствующий заголовок в ответе на загрузку blob (требуется клиентом Helm OCI)

### Security / Безопасность
- Read-only tokens (`role: read`) are now blocked from PUT/POST/DELETE/PATCH operations with HTTP 403
- Токены только для чтения (`role: read`) теперь блокируются при PUT/POST/DELETE/PATCH с HTTP 403

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.25] - 2026-03-03

### Fixed / Исправлено
- **Rate limiter fix**: Added `NORA_RATE_LIMIT_ENABLED` env var (default: `true`) to disable rate limiting on internal deployments
- **Исправление rate limiter**: Добавлена переменная `NORA_RATE_LIMIT_ENABLED` (по умолчанию: `true`) для отключения rate limiting на внутренних инсталляциях
- **SmartIpKeyExtractor**: Upload and general routes now use `SmartIpKeyExtractor` (reads `X-Forwarded-For`) instead of `PeerIpKeyExtractor` — fixes 429 errors behind reverse proxy / Docker bridge
- **SmartIpKeyExtractor**: Маршруты upload и general теперь используют `SmartIpKeyExtractor` (читает `X-Forwarded-For`) вместо `PeerIpKeyExtractor` — устраняет ошибки 429 за reverse proxy / Docker bridge

### Dependencies / Зависимости
- `clap` 4.5.56 → 4.5.60
- `uuid` 1.20.0 → 1.21.0
- `tempfile` 3.24.0 → 3.26.0
- `bcrypt` 0.17.1 → 0.18.0
- `indicatif` 0.17.11 → 0.18.4

### CI/CD
- `actions/checkout` 4 → 6
- `actions/upload-artifact` 4 → 7
- `softprops/action-gh-release` 1 → 2
- `aquasecurity/trivy-action` 0.30.0 → 0.34.2
- `docker/build-push-action` 5 → 6
- Move scan/release to self-hosted runner with NORA cache
- Сканирование/релиз перенесены на self-hosted runner с кэшем через NORA

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.24] - 2026-02-24

### Added / Добавлено
- `install.sh` installer script live at <https://getnora.io/install.sh> — `curl -fsSL https://getnora.io/install.sh | sh`
- Скрипт установки `install.sh` доступен на <https://getnora.io/install.sh>

### CI/CD
- Restore Astra Linux SE Docker image build, Trivy scan, and release artifact (`-astra` tag)
- Восстановлена сборка Docker-образа для Astra Linux SE, сканирование Trivy и артефакт релиза (тег `-astra`)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.23] - 2026-02-24

### Added / Добавлено
- Binary (`nora`) + SHA-256 checksum attached to every GitHub Release
- Бинарник (`nora`) и SHA-256 контрольная сумма прикреплены к каждому релизу GitHub

### Fixed / Исправлено
- Security: bump `prometheus` 0.13 → 0.14 (CVE-2025-53605) and `bytes` 1.11.0 → 1.11.1 (CVE-2026-25541)
- Безопасность: обновлены `prometheus` 0.13 → 0.14 (CVE-2025-53605) и `bytes` 1.11.0 → 1.11.1 (CVE-2026-25541)

### CI/CD
- Add Dependabot for automated dependency updates / Добавлен Dependabot для автоматического обновления зависимостей
- Pin `aquasecurity/trivy-action` to `0.30.0`, bump to `0.34.1`; scan gate blocks release on HIGH/CRITICAL CVE
- Закреплён `trivy-action@0.30.0`, обновлён до `0.34.1`; сканирование блокирует релиз при HIGH/CRITICAL CVE
- Upgrade `codeql-action` v3 → v4 / Обновлён `codeql-action` v3 → v4
- Fix `deny.toml` deprecated keys (`copyleft`, `unlicensed` removed in `cargo-deny`) / Исправлены устаревшие ключи в `deny.toml`
- Fix binary path in Docker image (`/usr/local/bin/nora`) / Исправлен путь бинарника в Docker-образе
- Pin build job to `nora` runner label / Джоб сборки закреплён за runner'ом с меткой `nora`
- Allow `CDLA-Permissive-2.0` license (`webpki-roots`) / Разрешена лицензия `CDLA-Permissive-2.0`
- Ignore `RUSTSEC-2025-0119` (unmaintained transitive dep `number_prefix` via `indicatif`)

### Dependencies / Зависимости
- `chrono` 0.4.43 → 0.4.44
- `quick-xml` 0.31.0 → 0.39.2
- `toml` 0.8.23 → 1.0.3+spec-1.1.0
- `flate2` 1.1.8 → 1.1.9
- `softprops/action-gh-release` 1 → 2
- `actions/checkout` 4 → 6
- `docker/build-push-action` 5 → 6

### Documentation / Документация
- Replace text title with SVG logo; `O` styled in blue-600 / Заголовок заменён SVG-логотипом; буква `O` стилизована в blue-600

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.22] - 2026-02-24

### Changed / Изменено
- First stable release with Docker images published to container registry
- Первый стабильный релиз с Docker-образами, опубликованными в container registry

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.21] - 2026-02-24

### CI/CD
- Consolidate all Docker builds into a single job to fix runner network issues / Все Docker-сборки объединены в один job для устранения сетевых проблем runner'а
- Build musl static binary for maximum portability / Сборка musl-бинарника для максимальной переносимости
- Add security scanning (Trivy) + SBOM generation to release pipeline / Добавлено сканирование безопасности (Trivy) и генерация SBOM в pipeline релиза
- Add Cargo cache to speed up builds / Добавлен кэш Cargo для ускорения сборок
- Replace `gitleaks` GitHub Action with CLI (no license requirement) / `gitleaks` Action заменён CLI-вызовом (лицензия не требуется)
- Use GitHub-runner's own Rust toolchain (avoid path conflicts) / Используется Rust toolchain самого GitHub-runner'а
- Use shared runner filesystem instead of artifact API (avoids network upload latency) / Общая файловая система runner'а вместо artifact API
- Remove Astra Linux build temporarily / Сборка для Astra Linux временно удалена

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.20] - 2026-02-23

### Added / Добавлено
- Parallel CI builds for Astra Linux and RedOS / Параллельная сборка в CI для Astra Linux и RedOS

### Changed / Изменено
- Use `FROM scratch` base image for Astra Linux and RedOS Docker builds / Базовый образ `FROM scratch` для Docker-сборок Astra Linux и RedOS
- Shared `reqwest::Client` across all registry handlers / Общий `reqwest::Client` для всех registry-обработчиков

### Fixed / Исправлено
- Auth: replace `starts_with` with explicit `matches!` for token path checks / Аутентификация: `starts_with` заменён явной проверкой `matches!` для путей с токенами
- Remove unnecessary QEMU step for amd64-only builds / Удалён лишний шаг QEMU для amd64-сборок

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.19] - 2026-01-31

### Added / Добавлено
- Pre-commit hook to prevent accidental commits of sensitive files / Pre-commit хук для защиты от случайного коммита чувствительных файлов
- README badges: build status, version, license / Бейджи в README: статус сборки, версия, лицензия

### Performance / Производительность
- In-memory repository index with pagination for faster dashboard load / Индекс репозитория в памяти с пагинацией для ускорения загрузки дашборда

### Fixed / Исправлено
- Use `div_ceil` instead of manual ceiling division / Использован `div_ceil` вместо ручной реализации деления с округлением вверх

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.18] - 2026-01-31

### Changed
- Logo styling refinements

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.17] - 2026-01-31

### Added
- Copyright headers to all source files (Volkov Pavel | DevITWay)
- SPDX-License-Identifier: MIT in all .rs files

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.16] - 2026-01-31

### Changed
- N○RA branding: stylized O logo across dashboard
- Fixed O letter alignment in logo

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.15] - 2026-01-31

### Fixed
- Code formatting (cargo fmt)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.14] - 2026-01-31

### Fixed
- Docker dashboard now shows actual image size from manifest layers (config + layers sum)
- Previously showed only manifest file size (~500 B instead of actual image size)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.13] - 2026-01-31

### Fixed
- npm dashboard now shows correct version count and package sizes
- Parses metadata.json for versions, dist.unpackedSize, and time.modified
- Previously showed 0 versions / 0 B for all packages

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.12] - 2026-01-30

### Added

#### Configurable Rate Limiting
- Rate limits now configurable via `config.toml` and environment variables
- New config section `[rate_limit]` with parameters: `auth_rps`, `auth_burst`, `upload_rps`, `upload_burst`, `general_rps`, `general_burst`
- Environment variables: `NORA_RATE_LIMIT_{AUTH|UPLOAD|GENERAL}_{RPS|BURST}`

#### Secrets Provider Architecture
- Trait-based secrets management (`SecretsProvider` trait)
- ENV provider as default (12-Factor App pattern)
- Protected secrets with `zeroize` (memory zeroed on drop)
- Redacted Debug impl prevents secret leakage in logs
- New config section `[secrets]` with `provider` and `clear_env` options

#### Docker Image Metadata
- Support for image metadata retrieval

#### Documentation
- Bilingual onboarding guide (EN/RU)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.11] - 2026-01-26

### Added
- Internationalization (i18n) support
- PyPI registry proxy
- UI improvements

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.10] - 2026-01-26

### Changed
- Dark theme applied to all UI pages

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.9] - 2026-01-26

### Changed
- Version bump release

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.8] - 2026-01-26

### Added
- Dashboard endpoint added to OpenAPI documentation

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.7] - 2026-01-26

### Added
- Dynamic version display in UI sidebar

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.6] - 2026-01-26

### Added

#### Dashboard Metrics
- Global stats panel: downloads, uploads, artifacts, cache hit rate, storage
- Extended registry cards with artifact count, size, counters
- Activity log (last 20 events)

#### UI
- Dark theme (bg: #0f172a, cards: #1e293b)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.5] - 2026-01-26

### Fixed
- Docker push/pull: added PATCH endpoint for chunked uploads

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.4] - 2026-01-26

### Fixed
- Rate limiting: health/metrics endpoints now exempt
- Increased upload rate limits for Docker parallel requests

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.0] - 2026-01-25

### Added

#### UI: SVG Brand Icons
- Replaced emoji icons with proper SVG brand icons (Simple Icons style)
- Docker, Maven, npm, Cargo, PyPI icons now render as scalable vector graphics
- Consistent icon styling across dashboard, sidebar, and detail pages

#### Testing Infrastructure
- Unit tests for LocalStorage (8 tests): put/get, list, stat, health_check
- Unit tests for S3Storage with wiremock HTTP mocking (11 tests)
- Integration tests for auth/htpasswd (7 tests)
- Token lifecycle tests (11 tests)
- Validation tests (21 tests)
- **Total: 75 tests passing**

#### Security: Input Validation (`validation.rs`)
- Path traversal protection: rejects `../`, `..\\`, null bytes, absolute paths
- Docker image name validation per OCI distribution spec
- Content digest validation (`sha256:[64 hex]`, `sha512:[128 hex]`)
- Docker tag/reference validation
- Storage key length limits (max 1024 chars)

#### Security: Rate Limiting (`rate_limit.rs`)
- Auth endpoints: 1 req/sec, burst 5 (brute-force protection)
- Upload endpoints: 10 req/sec, burst 20
- General endpoints: 100 req/sec, burst 200
- Uses `tower_governor` 0.8 with `PeerIpKeyExtractor`

#### Observability: Request ID Tracking (`request_id.rs`)
- `X-Request-ID` header added to all responses
- Accepts upstream request ID or generates UUID v4
- Tracing spans include request_id for log correlation

#### CLI: Migrate Command (`migrate.rs`)
- `nora migrate --from local --to s3` - migrate between storage backends
- `--dry-run` flag for preview without copying
- Progress bar with indicatif
- Skips existing files in destination
- Summary statistics (migrated, skipped, failed, bytes)

#### Error Handling (`error.rs`)
- `AppError` enum with `IntoResponse` for Axum
- Automatic conversion from `StorageError` and `ValidationError`
- JSON error responses with request_id support

### Changed
- `StorageError` now uses `thiserror` derive macro
- `TokenError` now uses `thiserror` derive macro
- Storage wrapper validates keys before delegating to backend
- Docker registry handlers validate name, digest, reference inputs
- Body size limit set to 100MB default via `DefaultBodyLimit`

### Dependencies Added
- `thiserror = "2"` - typed error handling
- `tower_governor = "0.8"` - rate limiting
- `governor = "0.10"` - rate limiting backend
- `tempfile = "3"` (dev) - temporary directories for tests
- `wiremock = "0.6"` (dev) - HTTP mocking for S3 tests

### Files Added
- `src/validation.rs` - input validation module
- `src/migrate.rs` - storage migration module
- `src/error.rs` - application error types
- `src/request_id.rs` - request ID middleware
- `src/rate_limit.rs` - rate limiting configuration

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.1.0] - 2026-01-24

### Added
- Multi-protocol support: Docker Registry v2, Maven, npm, Cargo, PyPI
- Web UI dashboard
- Swagger UI (`/api-docs`)
- Storage backends: Local filesystem, S3-compatible
- Smart proxy/cache for Maven and npm
- Health checks (`/health`, `/ready`)
- Basic authentication (htpasswd with bcrypt)
- API tokens (revocable, per-user)
- Prometheus metrics (`/metrics`)
- JSON structured logging
- Environment variable configuration
- Graceful shutdown (SIGTERM/SIGINT)
- Backup/restore commands

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

# Журнал изменений (RU)

Все значимые изменения NORA документируются в этом файле.

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.12] - 2026-01-30

### Добавлено

#### Настраиваемый Rate Limiting
- Rate limits настраиваются через `config.toml` и переменные окружения
- Новая секция `[rate_limit]` с параметрами: `auth_rps`, `auth_burst`, `upload_rps`, `upload_burst`, `general_rps`, `general_burst`
- Переменные окружения: `NORA_RATE_LIMIT_{AUTH|UPLOAD|GENERAL}_{RPS|BURST}`

#### Архитектура Secrets Provider
- Trait-based управление секретами (`SecretsProvider` trait)
- ENV provider по умолчанию (12-Factor App паттерн)
- Защищённые секреты с `zeroize` (память обнуляется при drop)
- Redacted Debug impl предотвращает утечку секретов в логи
- Новая секция `[secrets]` с опциями `provider` и `clear_env`

#### Docker Image Metadata
- Поддержка получения метаданных образов

#### Документация
- Двуязычный onboarding guide (EN/RU)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.11] - 2026-01-26

### Добавлено
- Поддержка интернационализации (i18n)
- PyPI registry proxy
- Улучшения UI

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.10] - 2026-01-26

### Изменено
- Тёмная тема применена ко всем страницам UI

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.9] - 2026-01-26

### Изменено
- Релиз с обновлением версии

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.8] - 2026-01-26

### Добавлено
- Dashboard endpoint добавлен в OpenAPI документацию

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.7] - 2026-01-26

### Добавлено
- Динамическое отображение версии в сайдбаре UI

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.6] - 2026-01-26

### Добавлено

#### Dashboard Metrics
- Глобальная панель статистики: downloads, uploads, artifacts, cache hit rate, storage
- Расширенные карточки реестров с количеством артефактов, размером, счётчиками
- Лог активности (последние 20 событий)

#### UI
- Тёмная тема (bg: #0f172a, cards: #1e293b)

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.5] - 2026-01-26

### Исправлено
- Docker push/pull: добавлен PATCH endpoint для chunked uploads

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.4] - 2026-01-26

### Исправлено
- Rate limiting: health/metrics endpoints теперь исключены
- Увеличены лимиты upload для параллельных Docker запросов

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.0] - 2026-01-25

### Добавлено

#### UI: SVG иконки брендов
- Эмоджи заменены на SVG иконки брендов (стиль Simple Icons)
- Docker, Maven, npm, Cargo, PyPI теперь отображаются как векторная графика
- Единый стиль иконок на дашборде, сайдбаре и страницах деталей

#### Тестовая инфраструктура
- Unit-тесты для LocalStorage (8 тестов): put/get, list, stat, health_check
- Unit-тесты для S3Storage с HTTP-мокированием wiremock (11 тестов)
- Интеграционные тесты auth/htpasswd (7 тестов)
- Тесты жизненного цикла токенов (11 тестов)
- Тесты валидации (21 тест)
- **Всего: 75 тестов проходят**

#### Безопасность: Валидация ввода (`validation.rs`)
- Защита от path traversal: отклоняет `../`, `..\\`, null-байты, абсолютные пути
- Валидация имён Docker-образов по спецификации OCI distribution
- Валидация дайджестов (`sha256:[64 hex]`, `sha512:[128 hex]`)
- Валидация тегов и ссылок Docker
- Ограничение длины ключей хранилища (макс. 1024 символа)

#### Безопасность: Rate Limiting (`rate_limit.rs`)
- Auth endpoints: 1 req/sec, burst 5 (защита от брутфорса)
- Upload endpoints: 10 req/sec, burst 20
- Общие endpoints: 100 req/sec, burst 200
- Использует `tower_governor` 0.8 с `PeerIpKeyExtractor`

#### Наблюдаемость: Отслеживание Request ID (`request_id.rs`)
- Заголовок `X-Request-ID` добавляется ко всем ответам
- Принимает upstream request ID или генерирует UUID v4
- Tracing spans включают request_id для корреляции логов

#### CLI: Команда миграции (`migrate.rs`)
- `nora migrate --from local --to s3` - миграция между storage backends
- Флаг `--dry-run` для предпросмотра без копирования
- Прогресс-бар с indicatif
- Пропуск существующих файлов в destination
- Итоговая статистика (migrated, skipped, failed, bytes)

#### Обработка ошибок (`error.rs`)
- Enum `AppError` с `IntoResponse` для Axum
- Автоматическая конверсия из `StorageError` и `ValidationError`
- JSON-ответы об ошибках с поддержкой request_id

### Изменено
- `StorageError` теперь использует макрос `thiserror`
- `TokenError` теперь использует макрос `thiserror`
- Storage wrapper валидирует ключи перед делегированием backend
- Docker registry handlers валидируют name, digest, reference
- Лимит размера body установлен в 100MB через `DefaultBodyLimit`

### Добавлены зависимости
- `thiserror = "2"` - типизированная обработка ошибок
- `tower_governor = "0.8"` - rate limiting
- `governor = "0.10"` - backend для rate limiting
- `tempfile = "3"` (dev) - временные директории для тестов
- `wiremock = "0.6"` (dev) - HTTP-мокирование для S3 тестов

### Добавлены файлы
- `src/validation.rs` - модуль валидации ввода
- `src/migrate.rs` - модуль миграции хранилища
- `src/error.rs` - типы ошибок приложения
- `src/request_id.rs` - middleware для request ID
- `src/rate_limit.rs` - конфигурация rate limiting

---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.1.0] - 2026-01-24

### Добавлено
- Мульти-протокольная поддержка: Docker Registry v2, Maven, npm, Cargo, PyPI
- Web UI дашборд
- Swagger UI (`/api-docs`)
- Storage backends: локальная файловая система, S3-совместимое хранилище
- Умный прокси/кэш для Maven и npm
- Health checks (`/health`, `/ready`)
- Базовая аутентификация (htpasswd с bcrypt)
- API токены (отзываемые, per-user)
- Prometheus метрики (`/metrics`)
- JSON структурированное логирование
- Конфигурация через переменные окружения
- Graceful shutdown (SIGTERM/SIGINT)
- Команды backup/restore
