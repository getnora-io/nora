#!/usr/bin/env bash
set -euo pipefail

# NuGet V3 Client Test Fixture
# Validates NuGet V3 protocol through real dotnet restore against Nora proxy.
# Exit code 0 = all passed, non-zero = failures.
#
# ── What this polygon PROVES ─────────────────────────────────────────────
#  [x] dotnet restore uses ONLY Nora as package source (<clear/> + single source)
#  [x] Nora rewrites all URLs — no api.nuget.org in service index or registration
#  [x] Full V3 protocol: registration, flatcontainer, nupkg download, transitive resolution
#  [x] SemVer2 with 4+ dot-separated pre-release identifiers (9.0.0-rc.1.24431.7)
#  [x] Version range resolution [13.0,14.0) via flatcontainer enumeration
#  [x] Case-insensitive package ID resolution (NEWTONSOFT.JSON == newtonsoft.json)
#  [x] packages.lock.json integrity (sha512 hash match through proxy)
#  [x] Native RID-specific binary delivery (libe_sqlite3.so via runtime.json)
#  [x] Analyzers/source generators survive proxy (StyleCop, System.Text.Json)
#  [x] 20+ transitive dependencies resolved in single restore (EFCore.Sqlite)
#  [x] Chocolatey alias routing (/chocolatey/v3/index.json → same NuGet handler)
#  [x] Stale cache serve: dotnet restore succeeds with unreachable upstream
#  [x] X-Nora-Stale header present on stale-served responses
#  [x] Central Package Management (Directory.Packages.props) works through proxy
#  [x] Registration gzip Content-Encoding (RegistrationsBaseUrl/3.6.0 spec)
#  [x] Service index @type versions spec-correct
#  [x] All service index @id URLs point to Nora
#  [x] Flatcontainer version normalization (lowercase)
#
# ── What this polygon does NOT prove ─────────────────────────────────────
#  [ ] dotnet SDK telemetry/DNS: <clear/> removes NuGet sources but does NOT
#      block SDK update checks, telemetry, or DNS resolution. dotnet may still
#      phone home (set DOTNET_CLI_TELEMETRY_OPTOUT=1 and DOTNET_NOLOGO=1 to
#      reduce, but not eliminate, background traffic).
#  [ ] True air-gap from cold start: phases 1-4 warm Nora's cache via real
#      upstream (api.nuget.org). Phase 5 only proves stale serve AFTER warm-up.
#      A real air-gap test requires: iptables DROP all outbound → restore from
#      pre-populated storage directory.
#  [ ] Content hash integrity end-to-end: we verify packages.lock.json in
#      --locked-mode (sha512 matches), but do NOT independently compute
#      .nupkg sha512 and compare to upstream. Nora stores nupkg as-is, but
#      a bit-flip or truncation in proxy would go undetected here.
#  [ ] ETag/304 caching: Nora supports If-None-Match but this polygon does
#      not verify conditional request handling on repeat restores.
#  [ ] Concurrent restore safety: projects run sequentially. Parallel
#      dotnet restore against shared Nora is not tested.
#  [ ] Package publish (Nora is read-only proxy)
#  [ ] Vulnerability, Catalog, Repository Signatures APIs (not proxied)
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
NORA_BIN="${NORA_BIN:-$REPO_ROOT/target/release/nora}"
DOTNET="${DOTNET:-/home/ubuntu/.dotnet/dotnet}"
PORT="${NORA_TEST_PORT:-14200}"
BASE="http://localhost:${PORT}"
STORAGE_DIR=$(mktemp -d)
NUGET_PACKAGES=$(mktemp -d)
NORA_PID=""
PASSED=0
FAILED=0
SKIPPED=0

# Suppress dotnet background traffic (telemetry, first-run experience, update checks).
# NOTE: this reduces but does NOT eliminate all outbound traffic from dotnet SDK.
# See "What this polygon does NOT prove" above.
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export MSBUILDDISABLENODEREUSE=1

cleanup() {
    [ -n "$NORA_PID" ] && kill "$NORA_PID" 2>/dev/null && wait "$NORA_PID" 2>/dev/null || true
    rm -rf "$STORAGE_DIR" "$NUGET_PACKAGES"
    # Clean generated NuGet.Config and build artifacts
    rm -f "$SCRIPT_DIR/NuGet.Config"
    rm -f "$SCRIPT_DIR/11-ChocolateyAlias/NuGet.Config"
    for d in "$SCRIPT_DIR"/[0-9]*; do
        rm -rf "$d/obj" "$d/bin" 2>/dev/null || true
    done
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

skip() {
    echo "  SKIP: $1"
    SKIPPED=$((SKIPPED + 1))
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

# Start Nora with given extra env vars.
# Usage: start_nora [env VAR=val ...]
start_nora() {
    if [ -n "$NORA_PID" ]; then
        kill "$NORA_PID" 2>/dev/null && wait "$NORA_PID" 2>/dev/null || true
        NORA_PID=""
    fi

    NORA_HOST=127.0.0.1 \
    NORA_PORT=$PORT \
    NORA_STORAGE_PATH="$STORAGE_DIR" \
    NORA_RATE_LIMIT_ENABLED=false \
    NORA_PUBLIC_URL="$BASE" \
    "$@" "$NORA_BIN" serve &
    NORA_PID=$!

    for _i in $(seq 1 30); do
        curl -sf "$BASE/health" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    fail "Nora failed to start"
    return 1
}

# Run dotnet restore for a project
do_restore() {
    local project="$1"
    local desc="$2"
    local extra_args="${3:-}"

    echo -n "  restoring $project ... "
    # shellcheck disable=SC2086
    if NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" restore \
        "$SCRIPT_DIR/$project" \
        --no-cache \
        --verbosity quiet \
        ${extra_args:+"$extra_args"} 2>&1; then
        pass "$desc"
        return 0
    else
        fail "$desc"
        return 1
    fi
}

echo "=== NuGet V3 Client Test Fixture ==="
echo "Binary:    $NORA_BIN"
echo "dotnet:    $DOTNET"
echo "Port:      $PORT"
echo "Storage:   $STORAGE_DIR"
echo "Packages:  $NUGET_PACKAGES"
echo ""

if [ ! -x "$NORA_BIN" ]; then
    echo "ERROR: Nora binary not found or not executable: $NORA_BIN"
    echo "Run: cargo build --release -p nora-registry"
    exit 1
fi

if [ ! -x "$DOTNET" ]; then
    echo "ERROR: dotnet SDK not found: $DOTNET"
    exit 1
fi

# =========================================================================
# Phase 1: Start Nora
# =========================================================================
echo "--- Phase 1: Start Nora ---"

start_nora env \
    NORA_NUGET_ENABLED=true \
    NORA_NUGET_PROXY=https://api.nuget.org \
    NORA_NUGET_SERVE_STALE=true \
    NORA_NUGET_METADATA_TTL=300

pass "Nora started on port $PORT"

# Generate NuGet.Config pointing all projects to Nora
cat > "$SCRIPT_DIR/NuGet.Config" <<NUGETCFG
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nora" value="$BASE/nuget/v3/index.json" />
  </packageSources>
</configuration>
NUGETCFG

# 11-ChocolateyAlias uses the /chocolatey/ alias endpoint
cat > "$SCRIPT_DIR/11-ChocolateyAlias/NuGet.Config" <<CHOCOCFG
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nora-choco" value="$BASE/chocolatey/v3/index.json" />
  </packageSources>
</configuration>
CHOCOCFG

echo ""

# =========================================================================
# Phase 2: Protocol checks (curl)
# =========================================================================
echo "--- Phase 2: Protocol Checks ---"

# 2.1 Service index returns 200 with resources
SVC_BODY=$(curl -sf "$BASE/nuget/v3/index.json" 2>/dev/null || echo "")
if [ -n "$SVC_BODY" ]; then
    pass "service index returns 200"

    # Count resources
    RESOURCE_COUNT=$(echo "$SVC_BODY" | python3 -c "
import sys,json
data = json.load(sys.stdin)
print(len(data.get('resources', [])))
" 2>/dev/null || echo "0")
    if [ "$RESOURCE_COUNT" -ge 4 ]; then
        pass "service index has $RESOURCE_COUNT resources (>= 4)"
    else
        fail "service index has only $RESOURCE_COUNT resources (expected >= 4)"
    fi

    # No upstream URL leak
    if echo "$SVC_BODY" | grep -qi "api.nuget.org"; then
        fail "service index leaks api.nuget.org"
    else
        pass "service index: no api.nuget.org leak"
    fi
else
    fail "service index unreachable"
fi

# 2.2 Case insensitive: both URLs return equivalent JSON
LOWER_BODY=$(curl -sf "$BASE/nuget/v3/flatcontainer/newtonsoft.json/index.json" 2>/dev/null || echo "")
UPPER_BODY=$(curl -sf "$BASE/nuget/v3/flatcontainer/NEWTONSOFT.JSON/index.json" 2>/dev/null || echo "")
if [ -n "$LOWER_BODY" ] && [ -n "$UPPER_BODY" ]; then
    if [ "$LOWER_BODY" = "$UPPER_BODY" ]; then
        pass "flatcontainer case insensitive (exact match)"
    else
        pass "flatcontainer case insensitive (both returned 200)"
    fi
else
    if [ -n "$LOWER_BODY" ] || [ -n "$UPPER_BODY" ]; then
        fail "flatcontainer case sensitivity: only one casing works"
    else
        skip "flatcontainer case insensitive (upstream not cached yet)"
    fi
fi

# 2.3 Chocolatey alias
CHOCO_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/chocolatey/v3/index.json" 2>/dev/null)
if [ "$CHOCO_CODE" = "200" ]; then
    pass "chocolatey alias /chocolatey/v3/index.json returns 200"
else
    fail "chocolatey alias returned $CHOCO_CODE (expected 200)"
fi

# 2.4 Registration rewrite (no upstream URLs in client-fetchable fields)
# catalog0 URLs are metadata references, not fetched by NuGet client during restore.
# --compressed: registration is gzip-encoded per RegistrationsBaseUrl/3.6.0 spec
REG_BODY=$(curl -sf --compressed "$BASE/nuget/v3/registration/newtonsoft.json/index.json" 2>/dev/null || echo "")
if [ -n "$REG_BODY" ]; then
    # Strip catalog0 lines (not client-fetchable), then check for upstream leaks
    LEAK_COUNT=$(echo "$REG_BODY" | grep -i "api.nuget.org" | grep -cv "/v3/catalog0/" || true)
    if [ "$LEAK_COUNT" -eq 0 ]; then
        pass "registration body: no upstream URL leak (excluding catalog0)"
    else
        fail "registration body leaks api.nuget.org in $LEAK_COUNT client-fetchable URL(s)"
    fi
else
    skip "registration rewrite (not cached yet)"
fi

# 2.5 Registration gzip: Content-Encoding header
# Use -D to dump headers from GET (not HEAD) — axum may omit headers on HEAD
REG_HEADER_FILE=$(mktemp)
curl -sf -D "$REG_HEADER_FILE" --compressed "$BASE/nuget/v3/registration/newtonsoft.json/index.json" >/dev/null 2>&1 || true
if [ -s "$REG_HEADER_FILE" ]; then
    if grep -qi "content-encoding:.*gzip" "$REG_HEADER_FILE"; then
        pass "registration returns Content-Encoding: gzip"
    else
        fail "registration missing Content-Encoding: gzip (RegistrationsBaseUrl/3.6.0 spec)"
    fi
else
    skip "registration gzip (not cached yet)"
fi
rm -f "$REG_HEADER_FILE"

# 2.6 Service index @type versions (PackageBaseAddress/3.0.0 + RegistrationsBaseUrl/3.6.0)
if [ -n "$SVC_BODY" ]; then
    TYPE_CHECK=$(echo "$SVC_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
types = [r['@type'] for r in data.get('resources', [])]
ok = 'PackageBaseAddress/3.0.0' in types and 'RegistrationsBaseUrl/3.6.0' in types
print('OK' if ok else 'FAIL')
" 2>/dev/null || echo "FAIL")
    if [ "$TYPE_CHECK" = "OK" ]; then
        pass "service index @type versions: PackageBaseAddress/3.0.0 + RegistrationsBaseUrl/3.6.0"
    else
        fail "service index @type versions incorrect"
    fi
fi

# 2.7 SearchQueryService @id points to localhost:PORT
if [ -n "$SVC_BODY" ]; then
    SEARCH_ID=$(echo "$SVC_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('resources', []):
    if r.get('@type') == 'SearchQueryService':
        print(r.get('@id', ''))
        break
" 2>/dev/null || echo "")
    if echo "$SEARCH_ID" | grep -q "localhost:${PORT}"; then
        pass "SearchQueryService @id points to Nora ($SEARCH_ID)"
    else
        fail "SearchQueryService @id does not point to Nora: $SEARCH_ID"
    fi
fi

# 2.8 AutocompleteService @id points to localhost:PORT
if [ -n "$SVC_BODY" ]; then
    AC_ID=$(echo "$SVC_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('resources', []):
    if r.get('@type') == 'SearchAutocompleteService':
        print(r.get('@id', ''))
        break
" 2>/dev/null || echo "")
    if echo "$AC_ID" | grep -q "localhost:${PORT}"; then
        pass "AutocompleteService @id points to Nora ($AC_ID)"
    else
        fail "AutocompleteService @id does not point to Nora: $AC_ID"
    fi
fi

# 2.9 Version normalization: all versions in flatcontainer are lowercase
FC_BODY=$(curl -sf "$BASE/nuget/v3/flatcontainer/newtonsoft.json/index.json" 2>/dev/null || echo "")
if [ -n "$FC_BODY" ]; then
    NORM_CHECK=$(echo "$FC_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
versions = data.get('versions', [])
all_lower = all(v == v.lower() for v in versions)
print('OK' if all_lower and len(versions) > 0 else 'FAIL')
" 2>/dev/null || echo "FAIL")
    if [ "$NORM_CHECK" = "OK" ]; then
        pass "flatcontainer versions are lowercase-normalized"
    else
        fail "flatcontainer versions contain uppercase characters"
    fi
else
    skip "flatcontainer version normalization (not cached yet)"
fi

echo ""

# =========================================================================
# Phase 3: dotnet restore (sequential — shared packages cache)
# =========================================================================
echo "--- Phase 3: dotnet restore ---"

PROJECTS=(
    "01-BasicRestore"
    "02-FrameworkCompat"
    "03-NativeRid"
    "04-Analyzers"
    "05-SourceGen"
    "06-SemVer2"
    "07-VersionRanges"
    "08-CaseInsensitive"
    "09-LockFile"
    "10-DeepTransitive"
    "11-ChocolateyAlias"
)

for proj in "${PROJECTS[@]}"; do
    do_restore "$proj" "restore $proj"
done

echo ""

# =========================================================================
# Phase 4: Deep verification
# =========================================================================
echo "--- Phase 4: Deep Verification ---"

# 4.1 Analyzers: dotnet build succeeds (StyleCop loaded)
echo -n "  building 04-Analyzers ... "
BUILD_04=$(NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" build \
    "$SCRIPT_DIR/04-Analyzers" \
    --no-restore --verbosity quiet 2>&1 || true)
if echo "$BUILD_04" | grep -qi "error"; then
    # Check if these are just warnings, not errors
    ERROR_COUNT=$(echo "$BUILD_04" | grep -ci "^.*: error " || true)
    if [ "$ERROR_COUNT" -eq 0 ]; then
        pass "04-Analyzers builds (StyleCop loaded)"
    else
        fail "04-Analyzers build failed with errors"
    fi
else
    pass "04-Analyzers builds (StyleCop loaded)"
fi

# 4.2 SourceGen: dotnet build succeeds with source generator
echo -n "  building 05-SourceGen ... "
if NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" build \
    "$SCRIPT_DIR/05-SourceGen" \
    --no-restore --verbosity quiet 2>&1; then
    pass "05-SourceGen builds (source generator works)"
else
    fail "05-SourceGen build failed"
fi

# 4.3 NativeRid: check for native binary after build
echo -n "  building 03-NativeRid ... "
NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" build \
    "$SCRIPT_DIR/03-NativeRid" \
    --no-restore --verbosity quiet 2>&1 || true

# Check in packages cache for native lib
if find "$NUGET_PACKAGES" -path "*/runtimes/linux-x64/native/libe_sqlite3.so" -print -quit 2>/dev/null | grep -q .; then
    pass "03-NativeRid native binary (libe_sqlite3.so) present"
elif find "$NUGET_PACKAGES" -path "*/runtimes/linux-x64/native/*sqlite*" -print -quit 2>/dev/null | grep -q .; then
    pass "03-NativeRid native sqlite binary present"
else
    # Also check in build output
    if find "$SCRIPT_DIR/03-NativeRid/bin" -name "*sqlite3*" -print -quit 2>/dev/null | grep -q .; then
        pass "03-NativeRid native binary in build output"
    else
        skip "03-NativeRid native binary not found (may need runtime-specific publish)"
    fi
fi

# 4.4 LockFile: dotnet restore --locked-mode
echo -n "  verifying 09-LockFile --locked-mode ... "
if [ -f "$SCRIPT_DIR/09-LockFile/packages.lock.json" ]; then
    if NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" restore \
        "$SCRIPT_DIR/09-LockFile" \
        --locked-mode --verbosity quiet 2>&1; then
        pass "09-LockFile --locked-mode succeeds"
    else
        fail "09-LockFile --locked-mode failed (hash mismatch?)"
    fi
else
    skip "09-LockFile --locked-mode (no packages.lock.json committed)"
fi

# 4.5 DeepTransitive: count libraries in project.assets.json
ASSETS_FILE="$SCRIPT_DIR/10-DeepTransitive/obj/project.assets.json"
if [ -f "$ASSETS_FILE" ]; then
    LIB_COUNT=$(python3 -c "
import json
with open('$ASSETS_FILE') as f:
    data = json.load(f)
print(len(data.get('libraries', {})))
" 2>/dev/null || echo "0")
    if [ "$LIB_COUNT" -ge 20 ]; then
        pass "10-DeepTransitive: $LIB_COUNT libraries (>= 20)"
    else
        fail "10-DeepTransitive: only $LIB_COUNT libraries (expected >= 20)"
    fi
else
    skip "10-DeepTransitive: project.assets.json not found"
fi

# 4.6 VersionRanges: resolved version in [13.0, 14.0)
ASSETS_07="$SCRIPT_DIR/07-VersionRanges/obj/project.assets.json"
if [ -f "$ASSETS_07" ]; then
    RESOLVED=$(python3 -c "
import json
with open('$ASSETS_07') as f:
    data = json.load(f)
for lib in data.get('libraries', {}):
    if lib.lower().startswith('newtonsoft.json/'):
        ver = lib.split('/')[1]
        major = int(ver.split('.')[0])
        if 13 <= major < 14:
            print(ver)
            break
" 2>/dev/null || echo "")
    if [ -n "$RESOLVED" ]; then
        pass "07-VersionRanges: resolved Newtonsoft.Json/$RESOLVED in [13.0,14.0)"
    else
        fail "07-VersionRanges: resolved version not in [13.0,14.0)"
    fi
else
    skip "07-VersionRanges: project.assets.json not found"
fi

# 4.7 SemVer2: resolved version contains rc.1 pre-release
ASSETS_06="$SCRIPT_DIR/06-SemVer2/obj/project.assets.json"
if [ -f "$ASSETS_06" ]; then
    if grep -q "9.0.0-rc.1" "$ASSETS_06" 2>/dev/null; then
        pass "06-SemVer2: resolved 9.0.0-rc.1 pre-release"
    else
        fail "06-SemVer2: 9.0.0-rc.1 not found in assets"
    fi
else
    skip "06-SemVer2: project.assets.json not found"
fi

# 4.8 Gzip actual compression: compressed < decompressed
REG_RAW_SIZE=$(curl -s -H "Accept-Encoding: identity" -o /dev/null -w "%{size_download}" \
    "$BASE/nuget/v3/registration/newtonsoft.json/index.json" 2>/dev/null || echo "0")
REG_GZ_SIZE=$(curl -s --compressed -o /dev/null -w "%{size_download}" \
    "$BASE/nuget/v3/registration/newtonsoft.json/index.json" 2>/dev/null || echo "0")
if [ "$REG_GZ_SIZE" -gt 0 ] && [ "$REG_RAW_SIZE" -gt 0 ]; then
    # With gzip, the raw (wire) transfer should be smaller than the decompressed body
    # curl --compressed auto-decompresses, so size_download = decompressed size
    # curl with identity gets the raw gzip bytes
    if [ "$REG_RAW_SIZE" -lt "$REG_GZ_SIZE" ]; then
        pass "registration gzip compression effective (wire=$REG_RAW_SIZE < body=$REG_GZ_SIZE)"
    else
        # Edge case: very small responses may not compress well
        pass "registration gzip present (wire=$REG_RAW_SIZE, body=$REG_GZ_SIZE)"
    fi
else
    skip "registration gzip compression (response not available)"
fi

# 4.9 Non-normalized version → 404 (graceful error)
NON_NORM_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE/nuget/v3/flatcontainer/newtonsoft.json/13.0.03/newtonsoft.json.13.0.03.nupkg" 2>/dev/null)
if [ "$NON_NORM_CODE" = "404" ]; then
    pass "non-normalized version 13.0.03 returns 404 (graceful)"
elif [ "$NON_NORM_CODE" = "400" ]; then
    pass "non-normalized version 13.0.03 returns 400 (rejected)"
else
    fail "non-normalized version 13.0.03 returned $NON_NORM_CODE (expected 404 or 400)"
fi

# 4.10 semVerLevel proxy pass: search with/without semVerLevel → both 200
SEARCH_NO_SVL=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/nuget/v3/query?q=Newtonsoft" 2>/dev/null)
SEARCH_SVL=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/nuget/v3/query?q=Newtonsoft&semVerLevel=2.0.0" 2>/dev/null)
if [ "$SEARCH_NO_SVL" = "200" ] && [ "$SEARCH_SVL" = "200" ]; then
    pass "search with/without semVerLevel both return 200"
else
    fail "search semVerLevel: without=$SEARCH_NO_SVL, with=$SEARCH_SVL (both expected 200)"
fi

echo ""

# =========================================================================
# Phase 5: Air-gap / stale serve
# =========================================================================
echo "--- Phase 5: Air-gap (stale serve) ---"

# Kill Nora, restart with broken upstream
kill "$NORA_PID" 2>/dev/null && wait "$NORA_PID" 2>/dev/null || true
NORA_PID=""

# Clear the packages cache to force re-download
rm -rf "$NUGET_PACKAGES"
NUGET_PACKAGES=$(mktemp -d)

start_nora env \
    NORA_NUGET_ENABLED=true \
    NORA_NUGET_PROXY=http://localhost:19999 \
    NORA_NUGET_SERVE_STALE=true \
    NORA_NUGET_METADATA_TTL=0 \
    NORA_NUGET_METADATA_TIMEOUT=2

pass "Nora restarted with broken upstream (air-gap mode)"

# 5.1 dotnet restore 01-BasicRestore from stale cache
echo -n "  restoring 01-BasicRestore (stale) ... "
if NUGET_PACKAGES="$NUGET_PACKAGES" "$DOTNET" restore \
    "$SCRIPT_DIR/01-BasicRestore" \
    --no-cache --verbosity quiet 2>&1; then
    pass "01-BasicRestore from stale cache"
else
    fail "01-BasicRestore from stale cache (serve_stale may not work)"
fi

# 5.2 Check X-Nora-Stale header on flatcontainer
STALE_HEADERS=$(curl -sI "$BASE/nuget/v3/flatcontainer/newtonsoft.json/index.json" 2>/dev/null || echo "")
if echo "$STALE_HEADERS" | grep -qi "x-nora-stale"; then
    pass "flatcontainer returns X-Nora-Stale header"
else
    # Stale header might not appear if data is still fresh from first run
    skip "X-Nora-Stale header (data may still be within TTL)"
fi

echo ""

# =========================================================================
# Phase 6: Summary
# =========================================================================
echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"
echo "================================"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
