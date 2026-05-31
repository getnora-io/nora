#!/usr/bin/env bash
# Post-Release Quality Gate — verify that a release actually landed correctly
# Checks: GitHub Release artifacts, binary, Docker images, cosign signatures, version consistency
# Usage: VERSION=0.8.2 ./scripts/post-release-gate.sh
# Dependencies: gh, docker, cosign, curl, jq

set -euo pipefail

REPO="getnora-io/nora"
GHCR_REGISTRY="ghcr.io/getnora-io/nora"
DOCKERHUB_REGISTRY="docker.io/getnora/nora"
VARIANTS=("" "-redos" "-astra")
BINARY_PORT="${GATE_PORT:-14100}"
DOCKER_PORT="$((BINARY_PORT + 100))"
PASSED=0
FAILED=0
VERSIONS_COLLECTED=()
WORK_DIR=$(mktemp -d)
CONTAINER_NAME="post-release-gate-$$"

cleanup() {
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

# Auto-detect version from latest release if not set
if [ -z "${VERSION:-}" ]; then
    VERSION=$(gh release view --repo "$REPO" --json tagName -q '.tagName' 2>/dev/null | sed 's/^v//')
    if [ -z "$VERSION" ]; then
        echo "ERROR: VERSION not set and could not detect latest release"
        exit 1
    fi
    echo "Auto-detected version: $VERSION"
fi

TAG="v${VERSION}"

echo "=== NORA Post-Release Quality Gate ==="
echo "Version: $VERSION (tag: $TAG)"
echo "Work dir: $WORK_DIR"
echo ""

# --- Phase A: GitHub Release Artifacts ---

echo "--- Phase A: GitHub Release Artifacts ---"

RELEASE_JSON=$(gh release view "$TAG" --repo "$REPO" --json tagName,assets 2>/dev/null || echo "")
if [ -n "$RELEASE_JSON" ]; then
    pass "Release $TAG exists"
else
    fail "Release $TAG not found"
    echo "Cannot continue without release. Exiting."
    exit 1
fi

EXPECTED_ASSETS=(
    "nora-linux-amd64"
    "nora-linux-amd64.sha256"
    "nora-linux-amd64.bundle"
    "nora-${TAG}.sbom.spdx.json"
    "nora-${TAG}.sbom.cdx.json"
)

ACTUAL_ASSETS=$(echo "$RELEASE_JSON" | jq -r '.assets[].name')
for asset in "${EXPECTED_ASSETS[@]}"; do
    if echo "$ACTUAL_ASSETS" | grep -qx "$asset"; then
        pass "Asset present: $asset"
    else
        fail "Asset missing: $asset"
    fi
done

echo ""

# --- Phase B: Binary Verification ---

echo "--- Phase B: Binary Verification ---"

cd "$WORK_DIR"

# Download binary and checksum
if gh release download "$TAG" --repo "$REPO" --pattern "nora-linux-amd64" --pattern "nora-linux-amd64.sha256" --dir "$WORK_DIR" 2>/dev/null; then
    pass "Downloaded binary + sha256"
else
    fail "Failed to download binary artifacts"
fi

# SHA256 verification
if [ -f "$WORK_DIR/nora-linux-amd64" ] && [ -f "$WORK_DIR/nora-linux-amd64.sha256" ]; then
    EXPECTED_SHA=$(awk '{print $1}' "$WORK_DIR/nora-linux-amd64.sha256")
    ACTUAL_SHA=$(sha256sum "$WORK_DIR/nora-linux-amd64" | awk '{print $1}')
    if [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ]; then
        pass "SHA256 checksum matches"
    else
        fail "SHA256 mismatch: expected=$EXPECTED_SHA actual=$ACTUAL_SHA"
    fi

    chmod +x "$WORK_DIR/nora-linux-amd64"

    # Version flag
    CLI_VERSION=$("$WORK_DIR/nora-linux-amd64" --version 2>/dev/null | awk '{print $2}' || echo "")
    if [ "$CLI_VERSION" = "$VERSION" ]; then
        pass "Binary --version = $VERSION"
        VERSIONS_COLLECTED+=("binary-cli=$CLI_VERSION")
    else
        fail "Binary --version = '$CLI_VERSION', expected '$VERSION'"
        [ -n "$CLI_VERSION" ] && VERSIONS_COLLECTED+=("binary-cli=$CLI_VERSION")
    fi

    # Health check via serve
    NORA_HOST=127.0.0.1 \
    NORA_PORT=$BINARY_PORT \
    NORA_STORAGE_PATH="$WORK_DIR/data" \
    NORA_RATE_LIMIT_ENABLED=false \
    "$WORK_DIR/nora-linux-amd64" serve &
    NORA_PID=$!

    HEALTHY=false
    for _ in $(seq 1 20); do
        if curl -sf "http://127.0.0.1:${BINARY_PORT}/health" >/dev/null 2>&1; then
            HEALTHY=true
            break
        fi
        sleep 0.5
    done

    if [ "$HEALTHY" = true ]; then
        HEALTH_JSON=$(curl -sf "http://127.0.0.1:${BINARY_PORT}/health" 2>/dev/null || echo "{}")
        HEALTH_VERSION=$(echo "$HEALTH_JSON" | jq -r '.version // empty' 2>/dev/null || echo "")
        if [ "$HEALTH_VERSION" = "$VERSION" ]; then
            pass "Binary /health version = $VERSION"
            VERSIONS_COLLECTED+=("binary-health=$HEALTH_VERSION")
        else
            fail "Binary /health version = '$HEALTH_VERSION', expected '$VERSION'"
            [ -n "$HEALTH_VERSION" ] && VERSIONS_COLLECTED+=("binary-health=$HEALTH_VERSION")
        fi
    else
        fail "Binary serve did not become healthy"
    fi

    kill "$NORA_PID" 2>/dev/null || true
    wait "$NORA_PID" 2>/dev/null || true
else
    fail "Binary or sha256 file not found after download"
fi

echo ""

# --- Phase C: Docker Images ---

echo "--- Phase C: Docker Images ---"

for registry in "$GHCR_REGISTRY" "$DOCKERHUB_REGISTRY"; do
    for variant in "${VARIANTS[@]}"; do
        IMAGE="${registry}:${VERSION}${variant}"
        SUFFIX="${variant:+${variant#-}}"
        LABEL="${registry##*/}/${SUFFIX:-alpine}"

        if docker pull "$IMAGE" >/dev/null 2>&1; then
            pass "Pull $IMAGE"
        else
            fail "Pull $IMAGE"
            continue
        fi

        # Run container, health check, verify version
        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
        docker run -d \
            --name "$CONTAINER_NAME" \
            -p "${DOCKER_PORT}:4000" \
            -e NORA_HOST=0.0.0.0 \
            "$IMAGE" >/dev/null 2>&1

        HEALTHY=false
        for _ in $(seq 1 15); do
            if curl -sf "http://127.0.0.1:${DOCKER_PORT}/health" >/dev/null 2>&1; then
                HEALTHY=true
                break
            fi
            sleep 1
        done

        if [ "$HEALTHY" = true ]; then
            DOCKER_HEALTH=$(curl -sf "http://127.0.0.1:${DOCKER_PORT}/health" 2>/dev/null || echo "{}")
            DOCKER_VERSION=$(echo "$DOCKER_HEALTH" | jq -r '.version // empty' 2>/dev/null || echo "")
            if [ "$DOCKER_VERSION" = "$VERSION" ]; then
                pass "Docker $LABEL /health version = $VERSION"
                VERSIONS_COLLECTED+=("docker-${LABEL}=$DOCKER_VERSION")
            else
                fail "Docker $LABEL /health version = '$DOCKER_VERSION', expected '$VERSION'"
                [ -n "$DOCKER_VERSION" ] && VERSIONS_COLLECTED+=("docker-${LABEL}=$DOCKER_VERSION")
            fi
        else
            echo "  --- docker logs $LABEL ---"
            docker logs "$CONTAINER_NAME" 2>&1 | tail -20 || true
            echo "  --- end logs ---"
            fail "Docker $LABEL did not become healthy"
        fi

        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    done
done

# Verify latest tag is pullable on GHCR
check "Pull ${GHCR_REGISTRY}:latest" \
    docker pull "${GHCR_REGISTRY}:latest"

echo ""

# --- Phase D: Signature Verification ---

echo "--- Phase D: Signature Verification ---"

# Download signature bundle
gh release download "$TAG" --repo "$REPO" \
    --pattern "nora-linux-amd64.bundle" \
    --dir "$WORK_DIR" --clobber 2>/dev/null || true

if [ -f "$WORK_DIR/nora-linux-amd64.bundle" ]; then
    if cosign verify-blob \
        --bundle "$WORK_DIR/nora-linux-amd64.bundle" \
        --certificate-identity-regexp "github.com/getnora-io/nora" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$WORK_DIR/nora-linux-amd64" >/dev/null 2>&1; then
        pass "cosign verify-blob binary signature"
    else
        fail "cosign verify-blob binary signature"
    fi
else
    fail "Signature bundle not available"
fi

# Verify GHCR alpine image signature
if cosign verify \
    --certificate-identity-regexp "github.com/getnora-io/nora" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${GHCR_REGISTRY}:${VERSION}" >/dev/null 2>&1; then
    pass "cosign verify GHCR alpine image"
else
    fail "cosign verify GHCR alpine image"
fi

echo ""

# --- Phase E: Version Consistency ---

echo "--- Phase E: Version Consistency ---"

ALL_MATCH=true
for entry in "${VERSIONS_COLLECTED[@]}"; do
    source_name="${entry%%=*}"
    source_ver="${entry#*=}"
    if [ "$source_ver" != "$VERSION" ]; then
        fail "Version mismatch: $source_name=$source_ver (expected $VERSION)"
        ALL_MATCH=false
    fi
done

if [ "$ALL_MATCH" = true ] && [ ${#VERSIONS_COLLECTED[@]} -gt 0 ]; then
    pass "All ${#VERSIONS_COLLECTED[@]} collected versions == $VERSION"
else
    if [ ${#VERSIONS_COLLECTED[@]} -eq 0 ]; then
        fail "No versions collected to compare"
    fi
fi

echo ""

# --- Summary ---

echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "================================"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
