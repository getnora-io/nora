#!/usr/bin/env bash
# changelog-fragments.sh — assemble changelog.d/*.md into CHANGELOG.md
#
# One file per change means parallel pull requests never edit the same lines, so they
# cannot conflict on the changelog. See changelog.d/README.md.
#
#   --check              fragments are well-formed (names, categories, non-empty)
#   --render             print the assembled section to stdout
#   --apply              write it into ## [Unreleased]
#   --release <version>  promote it to a dated version section and delete the fragments
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/changelog.d"
CHANGELOG="$ROOT/CHANGELOG.md"
MODE="${1:---check}"
VERSION="${2:-}"

python3 - "$ROOT" "$DIR" "$CHANGELOG" "$MODE" "$VERSION" <<'PY'
import datetime, os, re, sys

root, frag_dir, changelog, mode, version = sys.argv[1:6]
# Keep a Changelog order; anything else is a naming mistake, not a new section.
ORDER = ["added", "changed", "deprecated", "removed", "fixed", "security"]
NAME = re.compile(r"^(\d+)\.(" + "|".join(ORDER) + r")\.md$")

problems, entries = [], {c: [] for c in ORDER}
if os.path.isdir(frag_dir):
    for fn in sorted(os.listdir(frag_dir)):
        if fn == "README.md":
            continue
        m = NAME.match(fn)
        if not m:
            problems.append(
                f"{fn}: name must be <number>.<category>.md with category one of {', '.join(ORDER)}"
            )
            continue
        text = open(os.path.join(frag_dir, fn)).read().strip()
        if not text:
            problems.append(f"{fn}: empty")
            continue
        if text.startswith("- "):
            problems.append(f"{fn}: drop the leading '- ', the assembler adds it")
            continue
        entries[m.group(2)].append((int(m.group(1)), " ".join(text.split("\n"))))

if problems:
    for p in problems:
        print(f"FAIL: {p}")
    sys.exit(1)

section = []
for cat in ORDER:
    if not entries[cat]:
        continue
    section.append(f"### {cat.capitalize()}")
    for _, text in sorted(entries[cat]):
        section.append(f"- {text}")
    section.append("")
rendered = "\n".join(section).rstrip("\n")

if mode == "--check":
    total = sum(len(v) for v in entries.values())
    print(f"  OK: {total} fragment(s), all well-formed")
    sys.exit(0)
if mode == "--render":
    print(rendered)
    sys.exit(0)
if mode not in ("--apply", "--release"):
    print(f"FAIL: unknown mode {mode}")
    sys.exit(2)
if mode == "--release" and not version:
    print("FAIL: --release needs a version, e.g. --release 1.3.1")
    sys.exit(2)

lines = open(changelog).read().split("\n")
start = lines.index("## [Unreleased]")
end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## ["))
existing = [l for l in lines[start + 1:end] if l.strip()]
if existing and mode == "--apply":
    print("FAIL: ## [Unreleased] is not empty — fold those entries into changelog.d first")
    sys.exit(1)

if mode == "--apply":
    body = ["", rendered, ""] if rendered else [""]
    lines[start + 1:end] = body
else:
    today = datetime.date.today().isoformat()
    header = f"## [{version}] - {today}"
    lines[start + 1:end] = ["", header, "", rendered, ""] if rendered else [""]
    for fn in os.listdir(frag_dir):
        if fn != "README.md":
            os.remove(os.path.join(frag_dir, fn))

open(changelog, "w").write("\n".join(lines))
print(f"  OK: {mode[2:]} wrote {sum(len(v) for v in entries.values())} entry(ies)")
PY
