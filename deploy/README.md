# NORA Demo Deployment

[English](#english) | [Русский](#russian)

---

<a name="english"></a>
## English

### Quick Start

```bash
# Run NORA with Docker
docker run -d \
  --name nora \
  -p 4000:4000 \
  -v nora-data:/data \
  ghcr.io/getnora-io/nora:latest

# Check health
curl http://localhost:4000/health
```

### Push Docker Images

```bash
# Tag your image
docker tag myapp:v1 localhost:4000/myapp:v1

# Push to NORA
docker push localhost:4000/myapp:v1

# Pull from NORA
docker pull localhost:4000/myapp:v1
```

### Use as Maven Repository

```xml
<!-- pom.xml -->
<repositories>
  <repository>
    <id>nora</id>
    <url>http://localhost:4000/maven2/</url>
  </repository>
</repositories>
```

### Use as npm Registry

```bash
npm config set registry http://localhost:4000/npm/
npm install lodash
```

### Use as PyPI Index

```bash
pip install --index-url http://localhost:4000/simple/ requests
```

### Production Deployment with HTTPS

```bash
git clone https://github.com/getnora-io/nora.git
cd nora/deploy
docker compose up -d
```

### Reverse Proxy

When running NORA behind a reverse proxy (Caddy, Traefik, Nginx, etc.),
set `NORA_PUBLIC_URL` to your external domain. Without it, NORA generates
download URLs pointing to `http://0.0.0.0:4000`, which clients cannot reach.

```yaml
# docker-compose.yml
environment:
  - NORA_PUBLIC_URL=https://registry.example.com
```

**PyPI index URL** — use `/simple/`, not `/pypi/simple/`:

```bash
pip install --index-url https://registry.example.com/simple/ requests
```

**Self-signed TLS** — pip silently fails with "No matching distribution found"
unless you specify `--trusted-host` or `--cert`:

```bash
pip install \
  --index-url https://registry.example.com/simple/ \
  --trusted-host registry.example.com \
  requests
```

To make these settings permanent, create `~/.pip/pip.conf`:

```ini
[global]
index-url = https://registry.example.com/simple/
trusted-host = registry.example.com
```

### URLs

| URL | Description |
|-----|-------------|
| `/ui/` | Web UI |
| `/api-docs` | Swagger API Docs |
| `/health` | Health Check |
| `/metrics` | Prometheus Metrics |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_HOST` | 127.0.0.1 | Bind address |
| `NORA_PORT` | 4000 | Port |
| `NORA_STORAGE_PATH` | data/storage | Storage path |
| `NORA_AUTH_ENABLED` | false | Enable auth |

---

<a name="russian"></a>
## Русский

### Быстрый старт

```bash
# Запуск NORA в Docker
docker run -d \
  --name nora \
  -p 4000:4000 \
  -v nora-data:/data \
  ghcr.io/getnora-io/nora:latest

# Проверка работоспособности
curl http://localhost:4000/health
```

### Загрузка Docker образов

```bash
# Тегируем образ
docker tag myapp:v1 localhost:4000/myapp:v1

# Пушим в NORA
docker push localhost:4000/myapp:v1

# Скачиваем из NORA
docker pull localhost:4000/myapp:v1
```

### Использование как Maven репозиторий

```xml
<!-- pom.xml -->
<repositories>
  <repository>
    <id>nora</id>
    <url>http://localhost:4000/maven2/</url>
  </repository>
</repositories>
```

### Использование как npm реестр

```bash
npm config set registry http://localhost:4000/npm/
npm install lodash
```

### Использование как PyPI индекс

```bash
pip install --index-url http://localhost:4000/simple/ requests
```

### Продакшен с HTTPS

```bash
git clone https://github.com/getnora-io/nora.git
cd nora/deploy
docker compose up -d
```

### Reverse Proxy

При работе NORA за reverse proxy (Caddy, Traefik, Nginx и др.)
установите `NORA_PUBLIC_URL` на ваш внешний домен. Без этой переменной NORA
генерирует download-ссылки с `http://0.0.0.0:4000`, которые клиенты не могут достичь.

```yaml
# docker-compose.yml
environment:
  - NORA_PUBLIC_URL=https://registry.example.com
```

**URL для PyPI** — используйте `/simple/`, а не `/pypi/simple/`:

```bash
pip install --index-url https://registry.example.com/simple/ requests
```

**Самоподписанный TLS** — pip молча падает с ошибкой "No matching distribution found",
если не указать `--trusted-host` или `--cert`:

```bash
pip install \
  --index-url https://registry.example.com/simple/ \
  --trusted-host registry.example.com \
  requests
```

Для постоянной настройки создайте `~/.pip/pip.conf`:

```ini
[global]
index-url = https://registry.example.com/simple/
trusted-host = registry.example.com
```

### Эндпоинты

| URL | Описание |
|-----|----------|
| `/ui/` | Веб-интерфейс |
| `/api-docs` | Swagger документация |
| `/health` | Проверка здоровья |
| `/metrics` | Метрики Prometheus |

### Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `NORA_HOST` | 127.0.0.1 | Адрес привязки |
| `NORA_PORT` | 4000 | Порт |
| `NORA_STORAGE_PATH` | data/storage | Путь хранилища |
| `NORA_AUTH_ENABLED` | false | Включить авторизацию |

---

### Management / Управление

```bash
# Stop / Остановить
docker compose down

# Restart / Перезапустить
docker compose restart

# Logs / Логи
docker compose logs -f nora

# Update / Обновить
docker compose pull && docker compose up -d
```
