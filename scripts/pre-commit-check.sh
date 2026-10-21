#!/usr/bin/env bash
# Pre-commit / pre-release quality gate for NORA
# Validates version consistency across all version sources.
#
# Usage:
#   ./scripts/pre-commit-check.sh          — check Cargo.toml vs OpenAPI
#   ./scripts/pre-commit-check.sh v0.7.3   — also check against a tag

set -euo pipefail

ERRORS=0
CARGO_VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')

echo "=== NORA pre-commit checks ==="
echo "Cargo.toml version: ${CARGO_VERSION}"

# ── Check: OpenAPI version matches Cargo.toml ────────────────────────────────
OPENAPI_FILE="nora-registry/src/openapi.rs"
if [ -f "$OPENAPI_FILE" ]; then
    # POSIX sed, not `grep -P`: BSD grep (macOS) has no -P.
    OPENAPI_VERSION=$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$OPENAPI_FILE" | head -1)
    if [ -z "$OPENAPI_VERSION" ]; then
        echo "FAIL: no version found in ${OPENAPI_FILE}"
        ERRORS=$((ERRORS + 1))
    elif [ "$OPENAPI_VERSION" != "$CARGO_VERSION" ]; then
        echo "FAIL: OpenAPI version (${OPENAPI_VERSION}) != Cargo.toml (${CARGO_VERSION})"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK:   OpenAPI version matches"
    fi
fi

# ── Check: tag version matches Cargo.toml (when tag is provided) ─────────────
TAG="${1:-}"
if [ -n "$TAG" ]; then
    TAG_VERSION="${TAG#v}"
    if [ "$TAG_VERSION" != "$CARGO_VERSION" ]; then
        echo "FAIL: Tag version (${TAG_VERSION}) != Cargo.toml (${CARGO_VERSION})"
        echo "      Bump version in Cargo.toml before tagging!"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK:   Tag version matches Cargo.toml"
    fi
fi

# ── Check: Cargo.lock is consistent ──────────────────────────────────────────
if [ -f "Cargo.lock" ]; then
    # One POSIX awk: a grep without a match would end the script under pipefail before it
    # could say what is missing.
    LOCK_VERSION=$(awk -F'"' '$0 == "name = \"nora-registry\"" { getline; if ($1 == "version = ") print $2; exit }' Cargo.lock)
    if [ -z "$LOCK_VERSION" ]; then
        echo "FAIL: no nora-registry version found in Cargo.lock"
        ERRORS=$((ERRORS + 1))
    elif [ "$LOCK_VERSION" != "$CARGO_VERSION" ]; then
        echo "FAIL: Cargo.lock nora-registry version (${LOCK_VERSION}) != Cargo.toml (${CARGO_VERSION})"
        echo "      Run: cargo update --workspace"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK:   Cargo.lock version matches"
    fi
fi

echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo "=== ${ERRORS} version check(s) FAILED ==="
    exit 1
else
    echo "=== All version checks passed ==="
fi
