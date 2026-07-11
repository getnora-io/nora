#!/usr/bin/env bash
# Self-test for scripts/diff-coverage.py.
#
# Runs the diff-coverage gate's in-script unit tests (lcov parsing, diff-hunk
# parsing and line-range intersection) against fixed test data. No git, no
# filesystem state — the logic under test is pure. Mirrors the pattern of
# scripts/test-reland-filechanges.sh, which self-tests reland-build-filechanges.sh.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
python3 "$here/diff-coverage.py" --self-test
