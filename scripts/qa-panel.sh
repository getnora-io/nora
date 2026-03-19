#!/usr/bin/env bash
# ============================================================================
# NORA Pre-Release QA Panel
# Usage: ./qa-panel.sh [port] [storage_path]
#   port          — test server port (default: 4091)
#   storage_path  — temp storage dir (default: /tmp/nora-qa-$$)
#
# Requires: nora binary already built (./target/release/nora)
# Run from repo root: /srv/projects/nora/
#
# Exit codes: 0 = all passed, 1 = failures found
# ============================================================================

set -euo pipefail

PORT="${1:-4091}"
STORAGE="${2:-/tmp/nora-qa-$$}"
BINARY="./target/release/nora"
PASS=0
FAIL=0
TOTAL_START=$(date +%s)

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

check() {
    if [ "$1" = "$2" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $3"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[FAIL]${NC} $3 (got '$1', expected '$2')"
        FAIL=$((FAIL+1))
    fi
}

cleanup() {
    pkill -f "nora.*${PORT}" 2>/dev/null || true
    rm -rf "$STORAGE" 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================================
echo "======================================================================"
echo "  NORA Pre-Release QA Panel"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "  Port: $PORT | Storage: $STORAGE"
echo "======================================================================"
echo

# --- Phase 1: Static checks ---
echo "=== Phase 1: Static Analysis ==="

if [ -f "$BINARY" ]; then
    check "exists" "exists" "Binary exists"
    SIZE=$(du -sh "$BINARY" | cut -f1)
    echo "  [INFO] Binary size: $SIZE"
else
    check "missing" "exists" "Binary exists"
    echo "FATAL: Binary not found. Run: cargo build --release"
    exit 1
fi

echo

# --- Phase 2: Start server ---
echo "=== Phase 2: Server Startup ==="
rm -rf "$STORAGE"
NORA_STORAGE_PATH="$STORAGE" NORA_PORT="$PORT" NORA_HOST=127.0.0.1 \
    NORA_RATE_LIMIT_ENABLED=false "$BINARY" serve > "${STORAGE}.log" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 15); do
    curl -sf "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1 && break || sleep 1
done

if curl -sf "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1; then
    check "up" "up" "Server started (PID $SERVER_PID)"
    VERSION=$(curl -sf "http://127.0.0.1:${PORT}/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null || echo "?")
    echo "  [INFO] Version: $VERSION"
else
    check "down" "up" "Server started"
    echo "FATAL: Server failed to start. Log:"
    tail -20 "${STORAGE}.log"
    exit 1
fi

echo

# --- Phase 3: Endpoints ---
echo "=== Phase 3: Endpoint Health ==="
for EP in /health /ready /metrics /ui/ /api/ui/dashboard /api/ui/stats /v2/ /v2/_catalog /simple/ /api-docs; do
    CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${PORT}${EP}" 2>/dev/null || echo "000")
    if [ "$CODE" = "200" ] || [ "$CODE" = "303" ]; then
        check "$CODE" "$CODE" "GET $EP"
    else
        check "$CODE" "200" "GET $EP"
    fi
done

echo

# --- Phase 4: Security Hardening ---
echo "=== Phase 4: Security Hardening ==="

# SEC-001: .meta tag filter
mkdir -p "$STORAGE/docker/sec001/manifests"
echo '{}' > "$STORAGE/docker/sec001/manifests/v1.json"
echo '{}' > "$STORAGE/docker/sec001/manifests/v1.meta.json"
echo '{}' > "$STORAGE/docker/sec001/manifests/v2.json"
echo '{}' > "$STORAGE/docker/sec001/manifests/v2.meta.meta.json"
TAGS=$(curl -sf "http://127.0.0.1:${PORT}/v2/sec001/tags/list" 2>/dev/null || echo "{}")
echo "$TAGS" | grep -q "meta" && check "leaked" "filtered" "SEC-001: .meta tag filter" || check "filtered" "filtered" "SEC-001: .meta tag filter"

# SEC-002: Digest verification
DATA="qa-test-$(date +%s)"
DIGEST=$(echo -n "$DATA" | sha256sum | cut -d' ' -f1)
LOC=$(curl -sf -X POST "http://127.0.0.1:${PORT}/v2/sec002/blobs/uploads/" -D- -o /dev/null 2>&1 | grep -i location | tr -d '\r' | awk '{print $2}')
check "$(curl -sf -X PUT "http://127.0.0.1:${PORT}${LOC}?digest=sha256:${DIGEST}" -d "$DATA" -o /dev/null -w '%{http_code}')" "201" "SEC-002: valid SHA256 accepted"

LOC2=$(curl -sf -X POST "http://127.0.0.1:${PORT}/v2/sec002/blobs/uploads/" -D- -o /dev/null 2>&1 | grep -i location | tr -d '\r' | awk '{print $2}')
check "$(curl -sf -X PUT "http://127.0.0.1:${PORT}${LOC2}?digest=sha256:0000000000000000000000000000000000000000000000000000000000000000" -d "tampered" -o /dev/null -w '%{http_code}')" "400" "SEC-002: wrong digest rejected"

LOC3=$(curl -sf -X POST "http://127.0.0.1:${PORT}/v2/sec002/blobs/uploads/" -D- -o /dev/null 2>&1 | grep -i location | tr -d '\r' | awk '{print $2}')
check "$(curl -sf -X PUT "http://127.0.0.1:${PORT}${LOC3}?digest=sha512:$(python3 -c "print('a'*128)")" -d "x" -o /dev/null -w '%{http_code}')" "400" "SEC-002: sha512 rejected"

# SEC-004: Session limits
LOC4=$(curl -sf -X POST "http://127.0.0.1:${PORT}/v2/repo-a/blobs/uploads/" -D- -o /dev/null 2>&1 | grep -i location | tr -d '\r' | awk '{print $2}')
UUID4=$(echo "$LOC4" | grep -oP '[^/]+$')
check "$(curl -sf -X PATCH "http://127.0.0.1:${PORT}/v2/repo-b/blobs/uploads/${UUID4}" -d "x" -o /dev/null -w '%{http_code}')" "400" "SEC-004: session fixation blocked"
check "$(curl -sf -X PATCH "http://127.0.0.1:${PORT}/v2/t/blobs/uploads/nonexistent" -d "x" -o /dev/null -w '%{http_code}')" "404" "SEC-004: ghost session rejected"

# SEC-005: Security headers
HDRS=$(curl -sf -D- "http://127.0.0.1:${PORT}/health" -o /dev/null 2>&1)
echo "$HDRS" | grep -q "x-content-type-options: nosniff" && check y y "SEC-005: X-Content-Type-Options" || check n y "SEC-005: X-Content-Type-Options"
echo "$HDRS" | grep -q "x-frame-options: DENY" && check y y "SEC-005: X-Frame-Options" || check n y "SEC-005: X-Frame-Options"
echo "$HDRS" | grep -q "referrer-policy:" && check y y "SEC-005: Referrer-Policy" || check n y "SEC-005: Referrer-Policy"
echo "$HDRS" | grep -q "content-security-policy:" && check y y "SEC-005: CSP present" || check n y "SEC-005: CSP present"
echo "$HDRS" | grep -q "'self'" && check y y "SEC-005: CSP quotes correct" || check n y "SEC-005: CSP quotes correct"

# SEC-006: Namespaced catalog
mkdir -p "$STORAGE/docker/library/alpine/manifests"
echo '{}' > "$STORAGE/docker/library/alpine/manifests/latest.json"
CATALOG=$(curl -sf "http://127.0.0.1:${PORT}/v2/_catalog" 2>/dev/null || echo "{}")
echo "$CATALOG" | grep -q "library/alpine" && check y y "SEC-006: namespaced catalog" || check n y "SEC-006: namespaced catalog"

echo

# --- Phase 5: Protocol Round-Trips ---
echo "=== Phase 5: Protocol Round-Trips ==="

# Docker chunked upload flow
LOC5=$(curl -sf -X POST "http://127.0.0.1:${PORT}/v2/roundtrip/blobs/uploads/" -D- -o /dev/null 2>&1 | grep -i location | tr -d '\r' | awk '{print $2}')
BLOB="docker-roundtrip-test"
BDIGEST=$(echo -n "$BLOB" | sha256sum | cut -d' ' -f1)
curl -sf -X PATCH "http://127.0.0.1:${PORT}${LOC5}" -d "$BLOB" -o /dev/null
check "$(curl -sf -X PUT "http://127.0.0.1:${PORT}${LOC5}?digest=sha256:${BDIGEST}" -o /dev/null -w '%{http_code}')" "201" "Docker: chunked upload (POST→PATCH→PUT)"

# Maven
check "$(curl -sf -X PUT -d "maven-artifact" "http://127.0.0.1:${PORT}/maven2/com/test/a/1/a.jar" -o /dev/null -w '%{http_code}')" "201" "Maven: upload"
check "$(curl -sf -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/maven2/com/test/a/1/a.jar")" "200" "Maven: download"

# Raw
check "$(curl -sf -X PUT -d "raw-file" "http://127.0.0.1:${PORT}/raw/test/doc.txt" -o /dev/null -w '%{http_code}')" "201" "Raw: upload"
check "$(curl -sf -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/raw/test/doc.txt")" "200" "Raw: download"

echo

# --- Summary ---
TOTAL_END=$(date +%s)
DURATION=$((TOTAL_END - TOTAL_START))

echo "======================================================================"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}RESULT: $PASS passed, $FAIL failed${NC} (${DURATION}s)"
    echo "  STATUS: READY FOR RELEASE"
else
    echo -e "  ${RED}RESULT: $PASS passed, $FAIL failed${NC} (${DURATION}s)"
    echo "  STATUS: FIXES REQUIRED"
fi
echo "  Log: ${STORAGE}.log"
echo "======================================================================"

exit $FAIL
