# Changelog

All notable changes to NORA will be documented in this file.

---

## [0.2.18] - 2026-01-31

### Changed
- Logo styling refinements

---

## [0.2.17] - 2026-01-31

### Added
- Copyright headers to all source files (Volkov Pavel | DevITWay)
- SPDX-License-Identifier: MIT in all .rs files

---

## [0.2.16] - 2026-01-31

### Changed
- N○RA branding: stylized O logo across dashboard
- Fixed O letter alignment in logo

---

## [0.2.15] - 2026-01-31

### Fixed
- Code formatting (cargo fmt)

---

## [0.2.14] - 2026-01-31

### Fixed
- Docker dashboard now shows actual image size from manifest layers (config + layers sum)
- Previously showed only manifest file size (~500 B instead of actual image size)

---

## [0.2.13] - 2026-01-31

### Fixed
- npm dashboard now shows correct version count and package sizes
- Parses metadata.json for versions, dist.unpackedSize, and time.modified
- Previously showed 0 versions / 0 B for all packages

---

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

## [0.2.11] - 2026-01-26

### Added
- Internationalization (i18n) support
- PyPI registry proxy
- UI improvements

---

## [0.2.10] - 2026-01-26

### Changed
- Dark theme applied to all UI pages

---

## [0.2.9] - 2026-01-26

### Changed
- Version bump release

---

## [0.2.8] - 2026-01-26

### Added
- Dashboard endpoint added to OpenAPI documentation

---

## [0.2.7] - 2026-01-26

### Added
- Dynamic version display in UI sidebar

---

## [0.2.6] - 2026-01-26

### Added

#### Dashboard Metrics
- Global stats panel: downloads, uploads, artifacts, cache hit rate, storage
- Extended registry cards with artifact count, size, counters
- Activity log (last 20 events)

#### UI
- Dark theme (bg: #0f172a, cards: #1e293b)

---

## [0.2.5] - 2026-01-26

### Fixed
- Docker push/pull: added PATCH endpoint for chunked uploads

---

## [0.2.4] - 2026-01-26

### Fixed
- Rate limiting: health/metrics endpoints now exempt
- Increased upload rate limits for Docker parallel requests

---

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

# Журнал изменений (RU)

Все значимые изменения NORA документируются в этом файле.

---

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

## [0.2.11] - 2026-01-26

### Добавлено
- Поддержка интернационализации (i18n)
- PyPI registry proxy
- Улучшения UI

---

## [0.2.10] - 2026-01-26

### Изменено
- Тёмная тема применена ко всем страницам UI

---

## [0.2.9] - 2026-01-26

### Изменено
- Релиз с обновлением версии

---

## [0.2.8] - 2026-01-26

### Добавлено
- Dashboard endpoint добавлен в OpenAPI документацию

---

## [0.2.7] - 2026-01-26

### Добавлено
- Динамическое отображение версии в сайдбаре UI

---

## [0.2.6] - 2026-01-26

### Добавлено

#### Dashboard Metrics
- Глобальная панель статистики: downloads, uploads, artifacts, cache hit rate, storage
- Расширенные карточки реестров с количеством артефактов, размером, счётчиками
- Лог активности (последние 20 событий)

#### UI
- Тёмная тема (bg: #0f172a, cards: #1e293b)

---

## [0.2.5] - 2026-01-26

### Исправлено
- Docker push/pull: добавлен PATCH endpoint для chunked uploads

---

## [0.2.4] - 2026-01-26

### Исправлено
- Rate limiting: health/metrics endpoints теперь исключены
- Увеличены лимиты upload для параллельных Docker запросов

---

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
