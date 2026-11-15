#!/usr/bin/env bash
# test-pre-commit-check.sh — self-test for scripts/pre-commit-check.sh.
#
# The version check guards every commit and release tag. It must hold on the BSD
# userland of macOS (no `grep -P`, #1155), and a version it cannot read is a named
# failure, not the script stopping on its own error.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

# A grep that refuses -P, as BSD grep does; first on PATH for the "without GNU grep" runs.
mkdir -p "$TMP/bsd"
cat > "$TMP/bsd/grep" <<'SHIM'
#!/usr/bin/env bash
for a in "$@"; do
    case "$a" in -*P*) [ "${a#--}" = "$a" ] && { echo "grep: invalid option -- P" >&2; exit 2; } ;; esac
done
exec "$REAL_GREP" "$@"
SHIM
chmod +x "$TMP/bsd/grep"
export REAL_GREP="$(command -v grep)"

layout() { # cargo-version, openapi-line, lock-version (empty = no entry)
    rm -rf "$TMP/repo"; mkdir -p "$TMP/repo/scripts" "$TMP/repo/nora-registry/src"
    cp "$ROOT/scripts/pre-commit-check.sh" "$TMP/repo/scripts/"
    printf '[workspace.package]\nversion = "%s"\n' "$1" > "$TMP/repo/Cargo.toml"
    printf '#[openapi(\n    info(\n        title = "NORA",\n%s\n    )\n)]\n' "$2" > "$TMP/repo/nora-registry/src/openapi.rs"
    printf '[[package]]\nname = "nora-registry-ext"\nversion = "0.0.1"\n\n' > "$TMP/repo/Cargo.lock"
    [ -n "$3" ] && printf '[[package]]\nname = "nora-registry"\nversion = "%s"\n' "$3" >> "$TMP/repo/Cargo.lock"
    return 0
}

check() { # expected-rc, description, [path-prefix]
    local rc=0
    (cd "$TMP/repo" && PATH="${3:-}$PATH" bash scripts/pre-commit-check.sh) >"$TMP/out" 2>&1 || rc=$?
    # A refusal names what failed; a script that stops on its own error says nothing.
    if [ "$rc" = "$1" ] && { [ "$1" = 0 ] || grep -q '^FAIL: ' "$TMP/out"; }; then
        echo "  OK: $2"
    else
        echo "FAIL: $2 — rc=$rc, expected $1"; sed 's/^/      /' "$TMP/out"; FAILURES=$((FAILURES + 1))
    fi
}

for env in "" "$TMP/bsd:"; do
    name=${env:+without GNU grep}; name=${name:-with GNU grep}
    layout 1.4.0 '        version = "1.4.0",' 1.4.0
    check 0 "$name: matching versions pass" "$env"
    layout 1.4.0 '        version = "1.3.9",' 1.4.0
    check 1 "$name: another OpenAPI version fails" "$env"
    layout 1.4.0 '        description = "no version here",' 1.4.0
    check 1 "$name: an OpenAPI file without a version fails" "$env"
    layout 1.4.0 '        version = "1.4.0",' 1.3.9
    check 1 "$name: another Cargo.lock version fails" "$env"
    layout 1.4.0 '        version = "1.4.0",' ''
    check 1 "$name: a Cargo.lock without nora-registry fails" "$env"
done

# The shim is a real BSD-grep stand-in: it refuses -P and passes everything else.
if PATH="$TMP/bsd:$PATH" grep -oP 'x' <<<"x" >/dev/null 2>&1; then
    echo "FAIL: the -P shim accepted -P"; FAILURES=$((FAILURES + 1))
fi
if ! PATH="$TMP/bsd:$PATH" grep -o 'x' <<<"x" >/dev/null 2>&1; then
    echo "FAIL: the -P shim refused plain grep"; FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -gt 0 ]; then
    echo "=== ${FAILURES} pre-commit-check self-test(s) FAILED ==="
    exit 1
fi
echo "=== pre-commit-check self-test passed ==="
