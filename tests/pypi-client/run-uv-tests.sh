#!/usr/bin/env bash
set -euo pipefail

# PyPI client fixture: uv against a NORA proxy whose upstream publishes no hashes.
# Exit code 0 = all passed, non-zero = failures.
#
# ── What this polygon PROVES ─────────────────────────────────────────────
#  [x] uv resolves and installs through NORA when the upstream PEP 503 index has
#      links without #sha256= (#1100: uv refused NORA's PEP 691 JSON with
#      "missing field `hashes`")
#  [x] every file in NORA's PEP 691 JSON carries a `hashes` object
#  [x] uv talks only to NORA (single --default-index, no user config) and NORA
#      fetched the wheel from the fixture
#
# ── What this polygon does NOT prove ─────────────────────────────────────
#  [ ] behaviour against pypi.org itself (its links always carry #sha256=)
#  [ ] other uv versions than the one on PATH
#
# No network: the upstream is a local fixture serving a wheel built here.
#
# Usage: NORA_BIN=target/release/nora tests/pypi-client/run-uv-tests.sh

NORA_BIN="${NORA_BIN:-target/release/nora}"
UV="${UV:-uv}"
NORA_PORT="${NORA_PORT:-14180}"
UP_PORT="${UP_PORT:-14181}"

command -v "$UV" >/dev/null || { echo "FAIL: uv not found (set UV=)"; exit 2; }
[ -x "$NORA_BIN" ] || { echo "FAIL: NORA binary not found at $NORA_BIN (set NORA_BIN=)"; exit 2; }
NORA_BIN="$(cd "$(dirname "$NORA_BIN")" && pwd)/$(basename "$NORA_BIN")"

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }

# ── Fixture: a wheel and an upstream index that lists it without a hash ──
mkdir -p "$WORK/up/simple/nora-hashless"
python3 - "$WORK/up" <<'PY'
import sys, zipfile
root = sys.argv[1]
name = "nora_hashless-1.0.0-py3-none-any.whl"
files = {
    "nora_hashless/__init__.py": "VALUE = 1100\n",
    "nora_hashless-1.0.0.dist-info/METADATA":
        "Metadata-Version: 2.1\nName: nora-hashless\nVersion: 1.0.0\n",
    "nora_hashless-1.0.0.dist-info/WHEEL":
        "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}
record = "".join(f"{p},,\n" for p in files) + "nora_hashless-1.0.0.dist-info/RECORD,,\n"
with zipfile.ZipFile(f"{root}/{name}", "w") as z:
    for p, c in files.items():
        z.writestr(p, c)
    z.writestr("nora_hashless-1.0.0.dist-info/RECORD", record)
PY
cat > "$WORK/up/simple/nora-hashless/index.html" <<EOF
<!DOCTYPE html><html><body>
<a href="http://127.0.0.1:${UP_PORT}/nora_hashless-1.0.0-py3-none-any.whl">nora_hashless-1.0.0-py3-none-any.whl</a>
</body></html>
EOF
# http.server logs every request to stderr: the log shows what NORA fetched.
(cd "$WORK/up" && exec python3 -m http.server "$UP_PORT" --bind 127.0.0.1) \
    >"$WORK/upstream.log" 2>&1 &
PIDS+=($!)

# ── NORA: pypi proxy on the fixture, local storage, no auth ──
NORA_HOST=127.0.0.1 NORA_PORT="$NORA_PORT" NORA_PUBLIC_URL="http://127.0.0.1:${NORA_PORT}" \
NORA_STORAGE_PATH="$WORK/data" NORA_AUTH_ENABLED=false NORA_PYPI_ENABLED=true \
NORA_PYPI_PROXY="http://127.0.0.1:${UP_PORT}/simple/" \
    "$NORA_BIN" serve >"$WORK/nora.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:${NORA_PORT}/health" >/dev/null &&
        curl -sf "http://127.0.0.1:${UP_PORT}/simple/nora-hashless/" >/dev/null && break
    sleep 0.5
done
curl -sf "http://127.0.0.1:${NORA_PORT}/health" >/dev/null || { cat "$WORK/nora.log"; echo "FAIL: NORA did not start"; exit 1; }

# ── 1. The PEP 691 JSON itself ──
curl -sf -H 'Accept: application/vnd.pypi.simple.v1+json' \
    "http://127.0.0.1:${NORA_PORT}/simple/nora-hashless/" >"$WORK/index.json"
if python3 - "$WORK/index.json" <<'PY'
import json, sys
files = json.load(open(sys.argv[1]))["files"]
assert files, "no files listed"
for f in files:
    assert isinstance(f.get("hashes"), dict), f"{f['filename']}: hashes={f.get('hashes', '<absent>')!r}"
PY
then pass "every file in the PEP 691 JSON has a hashes object"
else fail "PEP 691 JSON: $(cat "$WORK/index.json")"
fi

# ── 2. uv resolves and installs through NORA only ──
export UV_NO_CONFIG=1 UV_CACHE_DIR="$WORK/uv-cache" UV_PYTHON_DOWNLOADS=never
unset UV_INDEX_URL UV_DEFAULT_INDEX UV_INDEX UV_EXTRA_INDEX_URL
mkdir "$WORK/proj"
cat >"$WORK/proj/pyproject.toml" <<'EOF'
[project]
name = "consumer"
version = "0.1.0"
requires-python = ">=3.8"
dependencies = ["nora-hashless==1.0.0"]

[tool.uv]
package = false
EOF
INDEX="http://127.0.0.1:${NORA_PORT}/simple/"
if (cd "$WORK/proj" && "$UV" lock --default-index "$INDEX") >"$WORK/uv-lock.log" 2>&1; then
    pass "uv lock through NORA"
else
    fail "uv lock through NORA:"; sed 's/^/    /' "$WORK/uv-lock.log"
fi
if (cd "$WORK/proj" && "$UV" sync --default-index "$INDEX" &&
    .venv/bin/python -c 'import nora_hashless, sys; sys.exit(nora_hashless.VALUE != 1100)') \
    >"$WORK/uv-sync.log" 2>&1; then
    pass "uv sync installs the package from NORA"
else
    fail "uv sync through NORA:"; sed 's/^/    /' "$WORK/uv-sync.log"
fi

if [ "$FAILED" = 0 ]; then
    if grep -q 'GET /nora_hashless-1.0.0-py3-none-any.whl' "$WORK/upstream.log"; then
        pass "NORA fetched the wheel from the upstream fixture"
    else
        fail "the wheel never went through the NORA proxy"
    fi
fi

echo "uv: $("$UV" --version)"
exit "$FAILED"
