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
