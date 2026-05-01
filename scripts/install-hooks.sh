#!/usr/bin/env bash
# Install git hooks for NORA development
# Usage: ./scripts/install-hooks.sh
#        make install-hooks

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "ERROR: not inside a git repository"
    exit 1
}

HOOKS_DIR="${REPO_ROOT}/.git/hooks"
PRE_COMMIT_SCRIPT="${REPO_ROOT}/scripts/pre-commit-check.sh"
PRE_COMMIT_HOOK="${HOOKS_DIR}/pre-commit"

if [ ! -f "${PRE_COMMIT_SCRIPT}" ]; then
    echo "ERROR: ${PRE_COMMIT_SCRIPT} not found"
    exit 1
fi

if [ -L "${PRE_COMMIT_HOOK}" ] && [ "$(readlink -f "${PRE_COMMIT_HOOK}")" = "$(readlink -f "${PRE_COMMIT_SCRIPT}")" ]; then
    echo "pre-commit hook already installed (symlink OK)"
    exit 0
fi

if [ -f "${PRE_COMMIT_HOOK}" ] && [ ! -L "${PRE_COMMIT_HOOK}" ]; then
    mv "${PRE_COMMIT_HOOK}" "${PRE_COMMIT_HOOK}.bak"
    echo "backed up existing pre-commit hook to ${PRE_COMMIT_HOOK}.bak"
fi

ln -sf "${PRE_COMMIT_SCRIPT}" "${PRE_COMMIT_HOOK}"
echo "pre-commit hook installed: ${PRE_COMMIT_HOOK} -> ${PRE_COMMIT_SCRIPT}"
