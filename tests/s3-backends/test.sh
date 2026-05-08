#!/usr/bin/env bash
set -euo pipefail

# S3 Backends E2E Test
# Runs smoke tests against NORA instances backed by different S3 implementations.
# Prerequisite: docker compose up -d (from this directory)

PASSED=0
FAILED=0
SKIPPED=0

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
}

skip() {
    echo "  SKIP: $1"
    SKIPPED=$((SKIPPED + 1))
}

# Wait for a NORA instance to be healthy (up to 30s)
wait_healthy() {
    local url="$1"
    for _ in $(seq 1 30); do
        if curl -sf "${url}/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Run tests for one backend
test_backend() {
    local name="$1"
    local base="$2"

    echo ""
    echo "=== ${name} (${base}) ==="

    # 1. Health check
    if ! wait_healthy "$base"; then
        fail "${name}: health check (not reachable after 30s)"
        return
    fi
    pass "${name}: health check"

    # 2. Raw upload/download — simple key
    local payload="s3-test-data-$(date +%s)"
    local http_code
    http_code=$(echo "$payload" | curl -s -o /dev/null -w "%{http_code}" \
        -X PUT --data-binary @- "${base}/raw/s3test/simple.txt")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        pass "${name}: raw upload (simple key)"
    else
        fail "${name}: raw upload (simple key) returned ${http_code}"
    fi

    local content
    content=$(curl -sf "${base}/raw/s3test/simple.txt" 2>/dev/null || echo "")
    if [ "$content" = "$payload" ]; then
        pass "${name}: raw download (simple key)"
    else
        fail "${name}: raw download (simple key) mismatch"
    fi

    # 3. Raw upload/download — key with @ (scoped package path)
    local at_payload="at-test-data-$(date +%s)"
    http_code=$(echo "$at_payload" | curl -s -o /dev/null -w "%{http_code}" \
        -X PUT --data-binary @- "${base}/raw/@scope/test.txt")
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        pass "${name}: raw upload (@ key)"
    else
        fail "${name}: raw upload (@ key) returned ${http_code}"
    fi

    content=$(curl -sf "${base}/raw/@scope/test.txt" 2>/dev/null || echo "")
    if [ "$content" = "$at_payload" ]; then
        pass "${name}: raw download (@ key)"
    else
        fail "${name}: raw download (@ key) mismatch"
    fi

    # 4. npm proxy — scoped package @babel/parser
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${base}/npm/@babel/parser")
    if [ "$http_code" = "200" ]; then
        pass "${name}: npm proxy @babel/parser"
    else
        # Some environments lack internet access for proxy
        skip "${name}: npm proxy @babel/parser (HTTP ${http_code}, may need internet)"
    fi

    # 5. HEAD on existing object (stat)
    http_code=$(curl -sf -o /dev/null -w "%{http_code}" --head "${base}/raw/s3test/simple.txt")
    if [ "$http_code" = "200" ]; then
        pass "${name}: HEAD existing object"
    else
        fail "${name}: HEAD existing object returned ${http_code}"
    fi

    # 6. 404 on nonexistent
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${base}/raw/nonexistent/does-not-exist.bin")
    if [ "$http_code" = "404" ]; then
        pass "${name}: 404 on nonexistent"
    else
        fail "${name}: nonexistent returned ${http_code}, expected 404"
    fi

    # 7. Delete
    curl -sf -X DELETE "${base}/raw/s3test/simple.txt" >/dev/null 2>&1 || true
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${base}/raw/s3test/simple.txt")
    if [ "$http_code" = "404" ]; then
        pass "${name}: delete object"
    else
        fail "${name}: deleted object still returns ${http_code}"
    fi

    # 8. Binary upload
    dd if=/dev/urandom bs=1024 count=8 2>/dev/null | \
        curl -sf -X PUT --data-binary @- "${base}/raw/s3test/binary.bin" >/dev/null 2>&1
    local bin_size
    bin_size=$(curl -sf "${base}/raw/s3test/binary.bin" 2>/dev/null | wc -c)
    if [ "$bin_size" -ge 8000 ]; then
        pass "${name}: binary upload/download (${bin_size} bytes)"
    else
        fail "${name}: binary size expected ~8192, got ${bin_size}"
    fi

    # 9. Reindex after direct S3 upload
    # Upload a file directly to S3 (bypassing NORA API), then verify
    # that POST /raw/-/reindex makes it appear in the index listing.
    # Note: NORA encodes @ → _at_ in S3 keys (SeaweedFS compat), so we
    # use a plain path without @ for this test.
    local reindex_key="raw/s3-direct/reindex-test.txt"
    local reindex_data="direct-upload-$(date +%s)"
    local uploaded=false

    case "$name" in
        RustFS)
            # Upload via mc in s3-tools container
            if echo "$reindex_data" | docker compose exec -T s3-tools \
                mc pipe "rustfs/nora-test/${reindex_key}" >/dev/null 2>&1; then
                uploaded=true
            fi
            ;;
        SeaweedFS)
            # SeaweedFS allows anonymous PUT via mapped port
            if echo "$reindex_data" | curl -sf -T - \
                "http://localhost:8333/nora-test/${reindex_key}" >/dev/null 2>&1; then
                uploaded=true
            fi
            ;;
        Garage)
            # Garage requires dynamic credentials from garage-init; skip
            skip "${name}: reindex (direct S3 upload requires dynamic Garage credentials)"
            uploaded=""
            ;;
    esac

    if [ "$uploaded" = "" ]; then
        # Already handled (skipped)
        :
    elif [ "$uploaded" = "true" ]; then
        # 9a. File should be readable via NORA storage (direct read, no index needed)
        content=$(curl -sf "${base}/raw/s3-direct/reindex-test.txt" 2>/dev/null || echo "")
        if [ "$content" = "$reindex_data" ]; then
            pass "${name}: direct S3 file readable via NORA"
        else
            fail "${name}: direct S3 file not readable via NORA (got '${content}')"
        fi

        # 9b. File should NOT be in the index listing yet (index is stale)
        local list_before
        list_before=$(curl -sf "${base}/api/ui/raw/list" 2>/dev/null || echo "[]")
        if echo "$list_before" | grep -q "s3-direct"; then
            # Index may have been rebuilt already (lazy rebuild); not a hard failure
            skip "${name}: reindex pre-check (index already contains s3-direct, lazy rebuild)"
        else
            pass "${name}: reindex pre-check (s3-direct not in stale index)"
        fi

        # 9c. POST /raw/-/reindex → 200
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${base}/raw/-/reindex")
        if [ "$http_code" = "200" ]; then
            pass "${name}: POST /raw/-/reindex returns 200"
        else
            fail "${name}: POST /raw/-/reindex returned ${http_code}"
        fi

        # 9d. After reindex, file should appear in the index listing
        local list_after
        list_after=$(curl -sf "${base}/api/ui/raw/list" 2>/dev/null || echo "[]")
        if echo "$list_after" | grep -q "s3-direct"; then
            pass "${name}: reindex updated index (s3-direct found in listing)"
        else
            fail "${name}: reindex did not update index (s3-direct not in listing)"
        fi
    else
        fail "${name}: direct S3 upload failed"
    fi
}

echo "=============================="
echo "NORA S3 Backends E2E Test"
echo "=============================="

# Define backends: name → localhost port
declare -A BACKENDS=(
    ["RustFS"]=15001
    ["SeaweedFS"]=15002
    ["Garage"]=15003
)

for name in RustFS SeaweedFS Garage; do
    port="${BACKENDS[$name]}"
    test_backend "$name" "http://localhost:${port}"
done

echo ""
echo "=============================="
echo "Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
echo "=============================="

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
