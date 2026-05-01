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
    OPENAPI_VERSION=$(grep -oP 'version\s*=\s*"\K[^"]+' "$OPENAPI_FILE" | head -1)
    if [ -n "$OPENAPI_VERSION" ] && [ "$OPENAPI_VERSION" != "$CARGO_VERSION" ]; then
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
    LOCK_VERSION=$(grep -A1 'name = "nora-registry"' Cargo.lock | grep -oP 'version = "\K[^"]+' | head -1)
    if [ -n "$LOCK_VERSION" ] && [ "$LOCK_VERSION" != "$CARGO_VERSION" ]; then
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
