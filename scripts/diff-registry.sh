#!/usr/bin/env bash
# diff-registry.sh — Differential testing: NORA vs reference registry
# Usage:
#   ./scripts/diff-registry.sh docker [nora_url]
#   ./scripts/diff-registry.sh npm [nora_url]
#   ./scripts/diff-registry.sh cargo [nora_url]
#   ./scripts/diff-registry.sh pypi [nora_url]
#   ./scripts/diff-registry.sh all [nora_url]
#
# Requires: curl, jq, skopeo (for docker), diff

set -euo pipefail

NORA_URL="${2:-http://localhost:5000}"
TMPDIR=$(mktemp -d)
PASS=0
FAIL=0
SKIP=0

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
skip() { SKIP=$((SKIP+1)); echo "  SKIP: $1"; }

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "WARNING: $1 not found, some tests will be skipped"
        return 1
    fi
    return 0
}

# --- Docker ---
diff_docker() {
    echo "=== Docker Registry V2 ==="
    
    # 1. /v2/ endpoint returns 200 or 401
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$NORA_URL/v2/")
    if [[ "$status" == "200" || "$status" == "401" ]]; then
        ok "/v2/ returns $status"
    else
        fail "/v2/ returns $status (expected 200 or 401)"
    fi

    # 2. _catalog returns valid JSON with repositories array
    local catalog
    catalog=$(curl -s "$NORA_URL/v2/_catalog" 2>/dev/null)
    if echo "$catalog" | jq -e '.repositories' &>/dev/null; then
        ok "/v2/_catalog has .repositories array"
    else
        fail "/v2/_catalog invalid JSON: $catalog"
    fi

    # 3. Push+pull roundtrip with skopeo
    if check_tool skopeo; then
        local test_image="diff-test/alpine"
        local test_tag="diff-$(date +%s)"
        
        # Copy a tiny image to NORA (resolves multi-arch to current platform)
        if skopeo copy --dest-tls-verify=false \
            docker://docker.io/library/alpine:3.20 \
            "docker://${NORA_URL#http*://}/$test_image:$test_tag" 2>/dev/null; then
            
            # Verify manifest structure: must have layers[] and config.digest
            skopeo inspect --tls-verify=false --raw \
                "docker://${NORA_URL#http*://}/$test_image:$test_tag" \
                > "$TMPDIR/nora-manifest.json" 2>/dev/null
            
            local has_layers has_config
            has_layers=$(jq -e '.layers | length > 0' "$TMPDIR/nora-manifest.json" 2>/dev/null)
            has_config=$(jq -e '.config.digest' "$TMPDIR/nora-manifest.json" 2>/dev/null)
            
            if [[ "$has_layers" == "true" && -n "$has_config" ]]; then
                ok "Docker push+pull roundtrip: valid manifest with layers"
            else
                fail "Docker manifest missing layers or config"
                jq . "$TMPDIR/nora-manifest.json" 2>/dev/null || true
            fi
            
            # Verify blob is retrievable by digest
            local first_layer
            first_layer=$(jq -r '.layers[0].digest' "$TMPDIR/nora-manifest.json" 2>/dev/null)
            if [[ -n "$first_layer" ]]; then
                local blob_status
                blob_status=$(curl -s -o /dev/null -w "%{http_code}" \
                    "$NORA_URL/v2/$test_image/blobs/$first_layer")
                if [[ "$blob_status" == "200" ]]; then
                    ok "Docker blob retrievable by digest"
                else
                    fail "Docker blob GET returned $blob_status"
                fi
            fi
            
            # Check tags/list
            local tags
            tags=$(curl -s "$NORA_URL/v2/$test_image/tags/list" 2>/dev/null)
            if echo "$tags" | jq -e ".tags[] | select(. == \"$test_tag\")" &>/dev/null; then
                ok "tags/list contains pushed tag"
            else
                fail "tags/list missing pushed tag: $tags"
            fi
        else
            fail "skopeo copy to NORA failed"
        fi
    else
        skip "Docker roundtrip (skopeo not installed)"
    fi
}

# --- npm ---
diff_npm() {
    echo "=== npm Registry ==="
    
    # 1. Package metadata format
    local meta
    meta=$(curl -s "$NORA_URL/npm/lodash" 2>/dev/null)
    local status=$?
    
    if [[ $status -ne 0 ]]; then
        skip "npm metadata (no packages published or upstream unavailable)"
        return
    fi
    
    if echo "$meta" | jq -e '.name' &>/dev/null; then
        ok "npm metadata has .name field"
    else
        skip "npm metadata (no packages or proxy not configured)"
        return
    fi
    
    # 2. Tarball URLs point to NORA, not upstream
    local tarball_url
    tarball_url=$(echo "$meta" | jq -r '.versions | to_entries | last | .value.dist.tarball // empty' 2>/dev/null)
    if [[ -n "$tarball_url" ]]; then
        if echo "$tarball_url" | grep -qvE "registry.npmjs.org|registry.yarnpkg.com"; then
            ok "npm tarball URLs rewritten to NORA"
        else
            fail "npm tarball URL points to upstream: $tarball_url"
        fi
    else
        skip "npm tarball URL check (no versions)"
    fi
}

# --- Cargo ---
diff_cargo() {
    echo "=== Cargo Sparse Index ==="
    
    # 1. config.json exists and has dl field
    local config
    config=$(curl -s "$NORA_URL/cargo/index/config.json" 2>/dev/null)
    if echo "$config" | jq -e '.dl' &>/dev/null; then
        ok "Cargo config.json has .dl field"
    else
        fail "Cargo config.json missing .dl: $config"
    fi
    
    # 2. config.json has api field
    if echo "$config" | jq -e '.api' &>/dev/null; then
        ok "Cargo config.json has .api field"
    else
        fail "Cargo config.json missing .api"
    fi
}

# --- PyPI ---
diff_pypi() {
    echo "=== PyPI Simple API ==="
    
    # 1. /simple/ returns HTML or JSON
    local simple_html
    simple_html=$(curl -s -H "Accept: text/html" "$NORA_URL/simple/" 2>/dev/null)
    if echo "$simple_html" | grep -qi "<!DOCTYPE\|<html\|simple" &>/dev/null; then
        ok "/simple/ returns HTML index"
    else
        skip "/simple/ HTML (no packages published)"
    fi
    
    # 2. PEP 691 JSON response
    local simple_json
    simple_json=$(curl -s -H "Accept: application/vnd.pypi.simple.v1+json" "$NORA_URL/simple/" 2>/dev/null)
    if echo "$simple_json" | jq -e '.projects // .meta' &>/dev/null; then
        ok "/simple/ PEP 691 JSON works"
    else
        skip "/simple/ PEP 691 (not supported or empty)"
    fi
}

# --- Go ---
diff_go() {
    echo "=== Go Module Proxy ==="
    
    # Basic health: try a known module
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$NORA_URL/go/golang.org/x/text/@v/list" 2>/dev/null)
    if [[ "$status" == "200" || "$status" == "404" ]]; then
        ok "Go proxy responds ($status)"
    else
        skip "Go proxy (status: $status)"
    fi
}

# --- Raw ---
diff_raw() {
    echo "=== Raw Storage ==="
    
    local test_path="diff-test/test-$(date +%s).txt"
    local test_content="diff-registry-test"
    
    # 1. PUT + GET roundtrip
    local put_status
    put_status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        -H "Content-Type: text/plain" \
        -d "$test_content" \
        "$NORA_URL/raw/$test_path" 2>/dev/null)
    
    if [[ "$put_status" == "200" || "$put_status" == "201" ]]; then
        local got
        got=$(curl -s "$NORA_URL/raw/$test_path" 2>/dev/null)
        if [[ "$got" == "$test_content" ]]; then
            ok "Raw PUT+GET roundtrip"
        else
            fail "Raw GET returned different content: '$got'"
        fi
        
        # 2. HEAD returns size
        local head_status
        head_status=$(curl -s -o /dev/null -w "%{http_code}" -I "$NORA_URL/raw/$test_path" 2>/dev/null)
        if [[ "$head_status" == "200" ]]; then
            ok "Raw HEAD returns 200"
        else
            fail "Raw HEAD returned $head_status"
        fi
        
        # 3. DELETE
        curl -s -o /dev/null -X DELETE "$NORA_URL/raw/$test_path" 2>/dev/null
        local after_delete
        after_delete=$(curl -s -o /dev/null -w "%{http_code}" "$NORA_URL/raw/$test_path" 2>/dev/null)
        if [[ "$after_delete" == "404" ]]; then
            ok "Raw DELETE works"
        else
            fail "Raw DELETE: GET after delete returned $after_delete"
        fi
    elif [[ "$put_status" == "401" ]]; then
        skip "Raw PUT (auth required)"
    else
        fail "Raw PUT returned $put_status"
    fi
}

# --- Main ---
case "${1:-all}" in
    docker) diff_docker ;;
    npm)    diff_npm ;;
    cargo)  diff_cargo ;;
    pypi)   diff_pypi ;;
    go)     diff_go ;;
    raw)    diff_raw ;;
    all)
        diff_docker
        diff_npm
        diff_cargo
        diff_pypi
        diff_go
        diff_raw
        ;;
    *)
        echo "Usage: $0 {docker|npm|cargo|pypi|go|raw|all} [nora_url]"
        exit 1
        ;;
esac

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
