#!/usr/bin/env bash
# Coherence check — deterministic cross-layer consistency validation
# Catches: version drift, undocumented env vars, registry list mismatch
# Runs in CI (<5s, no dependencies beyond bash+grep)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ERRORS=0
WARNINGS=0

fail() { echo "FAIL: $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo "WARN: $1"; WARNINGS=$((WARNINGS + 1)); }
ok()   { echo "  OK: $1"; }

echo "=== NORA Coherence Check ==="
echo ""

# ── 1. Version sync: Cargo.toml (workspace) ↔ openapi.rs ──────────────────

CARGO_VERSION=$(grep -m1 '^version = ' "$REPO_ROOT/Cargo.toml" | grep -oP '"\K[^"]+')
OPENAPI_VERSION=$(grep -oP 'version = "\K[^"]+' "$REPO_ROOT/nora-registry/src/openapi.rs" | head -1)

echo "--- Version Sync ---"
if [ "$CARGO_VERSION" = "$OPENAPI_VERSION" ]; then
    ok "Cargo.toml ($CARGO_VERSION) = openapi.rs ($OPENAPI_VERSION)"
else
    fail "Cargo.toml ($CARGO_VERSION) != openapi.rs ($OPENAPI_VERSION)"
fi

# CHANGELOG should mention current version (unless Unreleased-only)
if grep -q "\[$CARGO_VERSION\]" "$REPO_ROOT/CHANGELOG.md"; then
    ok "CHANGELOG contains [$CARGO_VERSION]"
else
    warn "CHANGELOG missing [$CARGO_VERSION] — acceptable if version just bumped"
fi
echo ""

# ── 2. Env vars: README table ⊆ config.rs apply_env_overrides() ──────────

echo "--- Env Vars (README → Code) ---"
README_VARS=$(grep -oP 'NORA_[A-Z_]+' "$REPO_ROOT/README.md" | sort -u)
CODE_VARS=$(grep -oP 'NORA_[A-Z_]+' "$REPO_ROOT/nora-registry/src/config.rs" | sort -u)

for var in $README_VARS; do
    if echo "$CODE_VARS" | grep -qx "$var"; then
        ok "$var exists in code"
    else
        fail "$var in README but NOT in config.rs"
    fi
done
echo ""

# ── 3. Registry list consistency ──────────────────────────────────────────

echo "--- Registry List ---"
# Source of truth: Router mounts in main.rs or lib.rs
EXPECTED_REGISTRIES="docker maven npm cargo pypi go raw gems terraform ansible nuget pub conan"

for reg in $EXPECTED_REGISTRIES; do
    # Check README mentions it
    if grep -qi "$reg" "$REPO_ROOT/README.md"; then
        ok "README mentions $reg"
    else
        fail "README missing registry: $reg"
    fi
done
echo ""

# ── 4. allow(dead_code) budget ────────────────────────────────────────────

echo "--- Dead Code Budget ---"
DEAD_CODE_COUNT=$(grep -rc 'allow(dead_code)' "$REPO_ROOT/nora-registry/src/" 2>/dev/null | awk -F: '{s+=$2} END {print s}')
DEAD_CODE_BUDGET=35

if [ "$DEAD_CODE_COUNT" -le "$DEAD_CODE_BUDGET" ]; then
    ok "allow(dead_code): $DEAD_CODE_COUNT (budget: $DEAD_CODE_BUDGET)"
else
    fail "allow(dead_code): $DEAD_CODE_COUNT exceeds budget $DEAD_CODE_BUDGET — review new additions"
fi
echo ""

# ── 5. License file matches Cargo.toml ────────────────────────────────────

echo "--- License ---"
CARGO_LICENSE=$(grep -m1 '^license' "$REPO_ROOT/Cargo.toml" | grep -oP '"\K[^"]+' || echo "")
if [ -f "$REPO_ROOT/LICENSE" ]; then
    if [ "$CARGO_LICENSE" = "MIT" ] && grep -q "MIT License" "$REPO_ROOT/LICENSE"; then
        ok "Cargo.toml license ($CARGO_LICENSE) matches LICENSE file"
    elif [ -n "$CARGO_LICENSE" ]; then
        warn "Cargo.toml says $CARGO_LICENSE — verify LICENSE file matches"
    fi
else
    fail "LICENSE file missing"
fi
echo ""

# ── 6. Silent error swallowing: _ => None without logging ─────────────────

echo "--- Silent Error Check (storage/handlers) ---"
SILENT_ERRORS=0
# Find `_ => None` or `_ => { None }` patterns in critical paths without tracing nearby
while IFS=: read -r file line content; do
    # Check 3 lines above for tracing/log
    start=$((line > 3 ? line - 3 : 1))
    context=$(sed -n "${start},${line}p" "$file")
    if ! echo "$context" | grep -qE 'tracing::|log::|error!|warn!'; then
        warn "Silent error at $file:$line — consider adding tracing"
        SILENT_ERRORS=$((SILENT_ERRORS + 1))
    fi
done < <(grep -rn '_ => None\|_ => {\s*None' \
    "$REPO_ROOT/nora-registry/src/storage/" \
    "$REPO_ROOT/nora-registry/src/handlers/" \
    2>/dev/null || true)

if [ "$SILENT_ERRORS" -eq 0 ]; then
    ok "No silent error swallowing in storage/handlers"
fi
echo ""

# ── 7. Route path vs docs-site path consistency ──────────────────────────

echo "--- Route Path vs Docs ---"
DOCS_DIR="$REPO_ROOT/docs-site/src/content/docs/registries"
SRC_DIR="$REPO_ROOT/nora-registry/src/registry"

if [ -d "$DOCS_DIR" ] && [ -d "$SRC_DIR" ]; then
    # Path mismatches caught by field testing:
    # Docs path → Actual route → Problem
    # Each entry: docs_wrong_pattern|correct_pattern
    # If docs contain the wrong pattern and NOT the correct one → FAIL
    declare -A PATH_CHECKS=(
        [cargo]="/cargo/[^i]|/cargo/index/"    # docs say /cargo/ but route is /cargo/index/
        [pypi]="/pypi/simple|/simple/"          # docs say /pypi/simple/ but route is /simple/
        [maven]="/maven[^2]|/maven2"             # docs say /maven/ but route is /maven2/
    )

    for reg in "${!PATH_CHECKS[@]}"; do
        doc_file="$DOCS_DIR/$reg.md"
        [ ! -f "$doc_file" ] && continue

        IFS='|' read -r wrong_pattern correct_pattern <<< "${PATH_CHECKS[$reg]}"

        # Check if docs contain the correct path
        if grep -qP ":\d+${correct_pattern//\//\\/}" "$doc_file" 2>/dev/null; then
            ok "$reg: docs use correct client path ($correct_pattern)"
        else
            # Check if docs contain the wrong path
            if grep -qP ":\d+${wrong_pattern}" "$doc_file" 2>/dev/null; then
                fail "$reg: docs use wrong path (matches $wrong_pattern) — correct is $correct_pattern"
            else
                warn "$reg: could not verify path in docs — manual check needed"
            fi
        fi
    done
else
    warn "docs-site or registry src not found — skipping route path check"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────

echo "=== Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "Coherence check FAILED with $ERRORS error(s)."
    exit 1
fi

echo "Coherence check PASSED."
exit 0
