# NORA Demo Deployment

## DNS Setup

Add A record:
```
demo.getnora.io → <VPS_IP>
```

## Deploy

```bash
# Clone repo
git clone https://github.com/getnora-io/nora.git
cd nora/deploy

# Start
docker compose up -d

# Check logs
docker compose logs -f
```

## URLs

- **Web UI:** https://demo.getnora.io/ui/
- **API Docs:** https://demo.getnora.io/api-docs
- **Health:** https://demo.getnora.io/health

## Docker Usage

```bash
# Tag and push
docker tag myimage:latest demo.getnora.io/myimage:latest
docker push demo.getnora.io/myimage:latest

# Pull
docker pull demo.getnora.io/myimage:latest
```

## Management

```bash
# Stop
docker compose down

# Restart
docker compose restart

# View logs
docker compose logs -f nora
docker compose logs -f caddy

# Update
docker compose pull
docker compose up -d
```
