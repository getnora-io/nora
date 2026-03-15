# Release Runbook

## Release process

1. Update version in `nora-registry/Cargo.toml`
2. Update `CHANGELOG.md`
3. Commit: `chore: bump version to X.Y.Z`
4. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. CI builds binary + 3 Docker images (alpine, redos, astra)
6. CI runs trivy scan on all images
7. CI creates GitHub Release with binary, checksums, SBOM

## Deploy order

1. **ai-server** (internal) — update first, verify
2. **PROD** — update after ai-server is stable
3. **GHCR** — public images pushed by CI automatically

## Rollback

### Quick rollback (revert to previous version)

```bash
# On ai-server
docker pull ghcr.io/getnora-io/nora:PREVIOUS_VERSION
docker stop nora && docker rm nora
docker run -d --name nora -p 4000:4000 \
  -v /srv/nora-data:/data \
  ghcr.io/getnora-io/nora:PREVIOUS_VERSION
```

### Delete a broken release

```bash
# 1. Delete GitHub Release (keeps tag)
gh release delete vX.Y.Z --yes

# 2. Delete tag
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z

# 3. Delete GHCR images (all variants)
for suffix in "" "-redos" "-astra"; do
  gh api -X DELETE /user/packages/container/nora/versions \
    --jq ".[] | select(.metadata.container.tags[] | contains(\"X.Y.Z${suffix}\")) | .id" \
    | xargs -I{} gh api -X DELETE /user/packages/container/nora/versions/{}
done
```

### Binary rollback

```bash
curl -LO https://github.com/getnora-io/nora/releases/download/vPREVIOUS/nora-linux-amd64
chmod +x nora-linux-amd64
sudo mv nora-linux-amd64 /usr/local/bin/nora
sudo systemctl restart nora
```

## Verification after deploy

```bash
# Health check
curl -sf http://localhost:4000/health | jq .

# Docker API
curl -sf http://localhost:4000/v2/ | jq .

# Push test image
docker pull alpine:3.20
docker tag alpine:3.20 localhost:4000/test/alpine:smoke
docker push localhost:4000/test/alpine:smoke
docker pull localhost:4000/test/alpine:smoke
```

## Known issues

- Self-hosted runner uses localhost:5000 (NORA) for buildx cache.
  If NORA is down during release, build continues without cache (ignore-error=true).
- Trivy image scan runs after push to localhost:5000 but before GitHub Release.
  A failed scan blocks the release.
