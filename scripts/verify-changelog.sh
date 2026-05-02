#!/usr/bin/env bash
# verify-changelog.sh — Verify CHANGELOG claims against actual code
# Part of Protocol G (Changelog Verification Gate)
#
# Catches: phantom features, wrong env var names, inflated numbers
# Runs in CI (<5s, no dependencies beyond bash+grep)
#
# Usage:
#   ./scripts/verify-changelog.sh          # check latest version section
#   ./scripts/verify-changelog.sh 0.7.3    # check specific version section

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
CONFIG="$REPO_ROOT/nora-registry/src/config.rs"
SRC="$REPO_ROOT/nora-registry/src"
ERRORS=0
WARNINGS=0

fail() { echo "FAIL: $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo "WARN: $1"; WARNINGS=$((WARNINGS + 1)); }
ok()   { echo "  OK: $1"; }

# ── Extract target section from CHANGELOG ─────────────────────────────────

TARGET_VERSION="${1:-}"

if [ -n "$TARGET_VERSION" ]; then
    # Extract specific version section
    SECTION=$(awk -v ver="$TARGET_VERSION" '
        /^## \[/ { if (found) exit; if (index($0, "[" ver "]")) found=1 }
        found { print }
    ' "$CHANGELOG")
    if [ -z "$SECTION" ]; then
        echo "ERROR: Version [$TARGET_VERSION] not found in CHANGELOG.md"
        exit 1
    fi
else
    # Extract latest non-Unreleased section
    SECTION=$(awk '
        /^## \[Unreleased\]/ { next }
        /^## \[/ { n++ }
        n==1 { print }
        n==2 { exit }
    ' "$CHANGELOG")
    TARGET_VERSION=$(echo "$SECTION" | head -1 | grep -oP '\[\K[^\]]+' || echo "unknown")
fi

echo "=== NORA Changelog Verification ==="
echo "Checking: [$TARGET_VERSION]"
echo ""

# ── 1. Env vars: every NORA_* in section must exist in source ─────────────

echo "--- Env Vars (CHANGELOG → Code) ---"
CHANGELOG_VARS=$(echo "$SECTION" | grep -oP 'NORA_[A-Z][A-Z0-9_]+' | sort -u || true)

if [ -z "$CHANGELOG_VARS" ]; then
    ok "No env vars mentioned"
else
    for var in $CHANGELOG_VARS; do
        if grep -rq "$var" "$SRC/" 2>/dev/null; then
            ok "$var"
        else
            fail "$var in CHANGELOG but NOT in source code"
        fi
    done
fi
echo ""

# ── 2. Registry count claims ─────────────────────────────────────────────

echo "--- Registry Count ---"
# Actual count: registry source files minus mod.rs and docker_auth.rs
ACTUAL_REG=$(ls "$SRC/registry/" 2>/dev/null \
    | grep '\.rs$' \
    | grep -cvE '^(mod|docker_auth)\.rs$' || echo 0)

CLAIMED_COUNTS=$(echo "$SECTION" | grep -oP '\b(\d+)\s+registr' | grep -oP '^\d+' || true)

if [ -z "$CLAIMED_COUNTS" ]; then
    ok "No registry count claims"
else
    for count in $CLAIMED_COUNTS; do
        if [ "$count" -eq "$ACTUAL_REG" ]; then
            ok "\"$count registries\" matches actual ($ACTUAL_REG)"
        else
            fail "\"$count registries\" claimed but actual count is $ACTUAL_REG"
        fi
    done
fi
echo ""

# ── 3. Test count claims ─────────────────────────────────────────────────

echo "--- Test Count ---"
TEST_CLAIMS=$(echo "$SECTION" | grep -oP '(\d+)\s+(?:total\s+)?tests' | grep -oP '^\d+' || true)

if [ -z "$TEST_CLAIMS" ]; then
    ok "No test count claims"
else
    for count in $TEST_CLAIMS; do
        # Sanity: must be >0 and <10000
        if [ "$count" -gt 0 ] && [ "$count" -lt 10000 ]; then
            warn "\"$count tests\" claimed — run 'cargo test' to verify (skipped for speed)"
        else
            fail "\"$count tests\" — implausible number"
        fi
    done
fi
echo ""

# ── 4. Feature → code mapping ────────────────────────────────────────────

echo "--- Features (CHANGELOG → Code) ---"
# Extract bold **Feature Name** entries from Added/Changed/Fixed sections
FEATURES=$(echo "$SECTION" \
    | grep -oP '\*\*[A-Za-z][^*]{2,40}\*\*' \
    | sed 's/\*//g' \
    | sort -u \
    | head -20 || true)

if [ -z "$FEATURES" ]; then
    ok "No bold feature names found"
else
    while IFS= read -r feature; do
        [ -z "$feature" ] && continue

        # Strategy: try snake_case, then CamelCase, then first keyword
        snake=$(echo "$feature" | tr '[:upper:] -' '[:lower:]__' | tr -cd 'a-z0-9_')
        camel=$(echo "$feature" | sed 's/[- ]//g')

        if grep -rq "$snake" "$SRC/" 2>/dev/null; then
            ok "\"$feature\" → $snake"
        elif grep -rq "$camel" "$SRC/" 2>/dev/null; then
            ok "\"$feature\" → $camel"
        else
            # Try significant keywords (>4 chars, not common words)
            found=0
            for word in $(echo "$feature" | tr ' ' '\n'); do
                lc=$(echo "$word" | tr '[:upper:]' '[:lower:]')
                # Skip short/common words
                case "$lc" in
                    the|and|for|all|new|add|fix|per|via|now|with|from|into) continue ;;
                esac
                if [ ${#lc} -ge 4 ] && grep -riq "$lc" "$SRC/" 2>/dev/null; then
                    ok "\"$feature\" → partial match ($lc)"
                    found=1
                    break
                fi
            done
            if [ "$found" -eq 0 ]; then
                # Docs-only changes (GOVERNANCE, ROADMAP, etc.) are OK
                case "$feature" in
                    *GOVERNANCE*|*ROADMAP*|*CHANGELOG*|*README*|*SECURITY*|*ADOPTERS*|*FUNDING*)
                        ok "\"$feature\" → docs-only (no code expected)" ;;
                    *)
                        warn "\"$feature\" → not found in source (may be docs-only)" ;;
                esac
            fi
        fi
    done <<< "$FEATURES"
fi
echo ""

# ── 5. Cross-check: CHANGELOG version = Cargo.toml ──────────────────────

echo "--- Version Match ---"
CARGO_VERSION=$(grep -m1 '^version = ' "$REPO_ROOT/Cargo.toml" | grep -oP '"\K[^"]+')

if [ "$TARGET_VERSION" = "$CARGO_VERSION" ]; then
    ok "CHANGELOG [$TARGET_VERSION] = Cargo.toml [$CARGO_VERSION]"
elif [ "$TARGET_VERSION" = "unknown" ]; then
    warn "Could not parse version from CHANGELOG section"
else
    ok "Checking historical version [$TARGET_VERSION] (current: $CARGO_VERSION)"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────

echo "=== Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "Changelog verification FAILED with $ERRORS error(s)."
    exit 1
fi

echo "Changelog verification PASSED."
exit 0
