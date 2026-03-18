#!/usr/bin/env bash
set -euo pipefail

# NORA E2E Smoke Test
# Starts NORA, runs real-world scenarios, verifies results.
# Exit code 0 = all passed, non-zero = failures.

NORA_BIN="${NORA_BIN:-./target/release/nora}"
PORT="${NORA_TEST_PORT:-14000}"
BASE="http://localhost:${PORT}"
STORAGE_DIR=$(mktemp -d)
PASSED=0
FAILED=0
NORA_PID=""

cleanup() {
    [ -n "$NORA_PID" ] && kill "$NORA_PID" 2>/dev/null || true
    rm -rf "$STORAGE_DIR"
}
trap cleanup EXIT

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
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

echo "=== NORA Smoke Test ==="
echo "Binary: $NORA_BIN"
echo "Port:   $PORT"
echo "Storage: $STORAGE_DIR"
echo ""

# Start NORA
NORA_HOST=127.0.0.1 \
NORA_PORT=$PORT \
NORA_STORAGE_PATH="$STORAGE_DIR" \
NORA_RATE_LIMIT_ENABLED=false \
NORA_PUBLIC_URL="$BASE" \
"$NORA_BIN" serve &
NORA_PID=$!

# Wait for startup
for i in $(seq 1 20); do
    curl -sf "$BASE/health" >/dev/null 2>&1 && break
    sleep 0.5
done

echo "--- Health & Monitoring ---"
check "GET /health returns healthy" \
    curl -sf "$BASE/health"

check "GET /ready returns 200" \
    curl -sf "$BASE/ready"

check "GET /metrics returns prometheus" \
    curl -sf "$BASE/metrics"

echo ""
echo "--- npm Proxy ---"

# Fetch metadata — triggers proxy cache
METADATA=$(curl -sf "$BASE/npm/chalk" 2>/dev/null || echo "{}")

check "npm metadata returns 200" \
    curl -sf "$BASE/npm/chalk"

# URL rewriting check
TARBALL_URL=$(echo "$METADATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('versions',{}).get('5.4.1',{}).get('dist',{}).get('tarball',''))" 2>/dev/null || echo "")
if echo "$TARBALL_URL" | grep -q "localhost:${PORT}/npm"; then
    pass "npm tarball URL rewritten to NORA"
else
    fail "npm tarball URL not rewritten: $TARBALL_URL"
fi

# Fetch tarball
check "npm tarball download" \
    curl -sf "$BASE/npm/chalk/-/chalk-5.4.1.tgz" -o /dev/null

# Scoped package
check "npm scoped package @babel/parser" \
    curl -sf "$BASE/npm/@babel/parser"

# Publish
PUBLISH_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"smoke-test-pkg","versions":{"1.0.0":{"name":"smoke-test-pkg","version":"1.0.0","dist":{}}},"dist-tags":{"latest":"1.0.0"},"_attachments":{"smoke-test-pkg-1.0.0.tgz":{"data":"dGVzdA==","content_type":"application/octet-stream"}}}' \
    "$BASE/npm/smoke-test-pkg")
if [ "$PUBLISH_RESULT" = "201" ]; then
    pass "npm publish returns 201"
else
    fail "npm publish returned $PUBLISH_RESULT"
fi

# Version immutability
DUPE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"smoke-test-pkg","versions":{"1.0.0":{"name":"smoke-test-pkg","version":"1.0.0","dist":{}}},"dist-tags":{"latest":"1.0.0"},"_attachments":{"smoke-test-pkg-1.0.0.tgz":{"data":"dGVzdA==","content_type":"application/octet-stream"}}}' \
    "$BASE/npm/smoke-test-pkg")
if [ "$DUPE_RESULT" = "409" ]; then
    pass "npm version immutability (409 on duplicate)"
else
    fail "npm duplicate publish returned $DUPE_RESULT, expected 409"
fi

# Security: name mismatch
MISMATCH_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"evil-pkg","versions":{"1.0.0":{}},"_attachments":{"a.tgz":{"data":"dGVzdA=="}}}' \
    "$BASE/npm/lodash")
if [ "$MISMATCH_RESULT" = "400" ]; then
    pass "npm name mismatch rejected (400)"
else
    fail "npm name mismatch returned $MISMATCH_RESULT, expected 400"
fi

# Security: path traversal
TRAVERSAL_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -H "Content-Type: application/json" \
    -d '{"name":"test-pkg","versions":{"1.0.0":{}},"_attachments":{"../../etc/passwd":{"data":"dGVzdA=="}}}' \
    "$BASE/npm/test-pkg")
if [ "$TRAVERSAL_RESULT" = "400" ]; then
    pass "npm path traversal rejected (400)"
else
    fail "npm path traversal returned $TRAVERSAL_RESULT, expected 400"
fi

echo ""
echo "--- Maven ---"
check "Maven proxy download" \
    curl -sf "$BASE/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.pom" -o /dev/null

echo ""
echo "--- PyPI ---"
check "PyPI simple index" \
    curl -sf "$BASE/simple/"

check "PyPI package page" \
    curl -sf "$BASE/simple/requests/"

echo ""
echo "--- Docker ---"
check "Docker v2 check" \
    curl -sf "$BASE/v2/"

echo ""
echo "--- Raw ---"
echo "raw-test-data" | curl -sf -X PUT --data-binary @- "$BASE/raw/smoke/test.txt" >/dev/null 2>&1
check "Raw upload" \
    curl -sf "$BASE/raw/smoke/test.txt" -o /dev/null

echo ""
echo "--- UI & API ---"
check "UI dashboard loads" \
    curl -sf "$BASE/ui/"

check "OpenAPI docs" \
    curl -sf "$BASE/api-docs" -o /dev/null

# Dashboard stats — check npm count > 0 after proxy fetches
sleep 1
STATS=$(curl -sf "$BASE/ui/api/stats" 2>/dev/null || echo "{}")
NPM_COUNT=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('npm',0))" 2>/dev/null || echo "0")
if [ "$NPM_COUNT" -gt 0 ] 2>/dev/null; then
    pass "Dashboard npm count > 0 (got $NPM_COUNT)"
else
    fail "Dashboard npm count is $NPM_COUNT, expected > 0"
fi

echo ""
echo "--- Mirror CLI ---"
# Create a minimal lockfile
LOCKFILE=$(mktemp)
cat > "$LOCKFILE" << 'EOF'
{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test" },
    "node_modules/chalk": { "version": "5.4.1" }
  }
}
EOF
MIRROR_RESULT=$("$NORA_BIN" mirror --registry "$BASE" npm --lockfile "$LOCKFILE" 2>&1)
if echo "$MIRROR_RESULT" | grep -q "Failed:   0"; then
    pass "nora mirror npm --lockfile (0 failures)"
else
    fail "nora mirror: $MIRROR_RESULT"
fi
rm -f "$LOCKFILE"

echo ""
echo "================================"
echo "Results: $PASSED passed, $FAILED failed"
echo "================================"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
