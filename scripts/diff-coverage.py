#!/usr/bin/env python3
"""Diff-scoped coverage gate.

Computes coverage over only the new/changed ``.rs`` lines in a pull request
and fails the build when it drops below a threshold. Unlike tarpaulin's global
``fail-under`` floor (which gates the whole-repo percentage), this gates the
*incremental* coverage so a high-coverage repository does not regress
line-by-line on each PR.

Usage::

    python3 diff-coverage.py --lcov coverage/lcov.info --base <merge-base-sha> \\
        --threshold 70
    python3 diff-coverage.py --self-test

Inputs:
    --lcov       Path to an lcov.info file (tarpaulin's ``"Lcov"`` output).
    --base       The PR base SHA. The merge-base with HEAD is computed from it
                 so rebased/multiple-commit PRs diff against the right ancestor.
    --threshold  Minimum diff-scoped coverage percentage (default 70).

The script invokes ``git`` (``git merge-base``, ``git diff``) to discover
changed ``.rs`` line ranges, intersects them with the lcov ``DA:`` records, and
reports per-file gaps. Docs-only PRs (no changed, instrumentable ``.rs`` lines)
pass cleanly.

Only changed lines that carry a ``DA:`` record are counted — non-instrumentable
lines (comments, item declarations, ``use`` statements) are ignored, matching
the behaviour of diff-cover style tools. A changed line with ``DA:<line>,0`` is
uncovered; ``DA:<line>,<n>`` with ``n > 0`` is covered.

Scope note (ungated by design): the gate can only see lines tarpaulin
instruments. Changes in the ``exclude-files`` of ``tarpaulin.toml``
(e.g. ``nora-registry/src/ui/*``, ``main.rs``, ``openapi.rs``) and any
``#[cfg(...)]``-gated code not built in the coverage profile produce no ``DA:``
record, so they contribute zero instrumentable lines and are **not** gated by
this check — the whole-repo ``coverage`` job remains their only floor.
"""

import argparse
import os
import re
import subprocess
import sys

# Matches a unified-diff hunk header: @@ -<old>,<old_n> +<new>,<new_n> @@
# --unified=0 emits only added lines, but we read the new-side range from the
# header so a brand-new file (@@ -0,0 +1,N @@) is handled the same way.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_lcov(text):
    """Parse lcov text into ``{filepath: {line: hit_count}}``.

    Only ``SF:`` and ``DA:`` records are used. ``DA:<line>,<count>[,<checksum>]``
    gives the hit count for a line; count > 0 means covered, 0 means uncovered.
    """
    files = {}
    current = None
    for line in text.splitlines():
        if line.startswith("SF:"):
            current = line[3:].strip()
            files.setdefault(current, {})
        elif line.startswith("DA:") and current is not None:
            parts = line[3:].split(",")
            if len(parts) < 2:
                continue
            try:
                lineno = int(parts[0])
                count = int(parts[1])
            except ValueError:
                continue
            files[current][lineno] = count
        elif line == "end_of_record":
            current = None
    return files


def parse_diff_hunks(diff_text):
    """Parse ``git diff --unified=0`` output into ``{filepath: [(start, end)]}``.

    Returns new-file line ranges (the ``+`` side). The current file is tracked
    via the ``+++ b/<path>`` line, which is emitted for both added and modified
    files. ``+++ /dev/null`` (a deletion on the new side) clears the current
    file so its hunks are ignored.
    """
    files = {}
    current = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            files.setdefault(current, [])
        elif line.startswith("+++ /dev/null"):
            current = None
        else:
            m = _HUNK_RE.match(line)
            if m is not None and current is not None:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                if count > 0:
                    files[current].append((start, start + count - 1))
    return files


def normalize_path(path, root):
    """Normalize a source path to a repo-root-relative POSIX path.

    Tarpaulin's lcov ``SF:`` records are absolute paths; git diff paths are
    already relative (``nora-registry/src/lib.rs``). Normalizing both to a
    root-relative form makes them directly comparable.
    """
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    if os.path.isabs(p):
        try:
            p = os.path.relpath(p, root).replace("\\", "/")
        except ValueError:
            # Different drive letters on Windows — fall back to the raw path.
            pass
    return p


def _lookup_hits(norm_lcov, diff_path):
    """Find the lcov hit-map for a diff path, with a suffix-match fallback."""
    if diff_path in norm_lcov:
        return norm_lcov[diff_path]
    for key, hits in norm_lcov.items():
        if key.endswith("/" + diff_path) or diff_path.endswith("/" + key):
            return hits
    return None


def intersect(lcov_files, diff_ranges, root):
    """Intersect lcov hits with changed-line ranges.

    Returns ``{filepath: {"covered": set, "uncovered": set}}``. Only changed
    lines that have a ``DA:`` record are classified; changed lines with no
    record (non-instrumentable) are ignored. A changed file with no lcov data
    contributes zero covered and zero uncovered lines.
    """
    norm_lcov = {}
    for sf, hits in lcov_files.items():
        norm_lcov[normalize_path(sf, root)] = hits

    result = {}
    for diff_path, ranges in diff_ranges.items():
        hits = _lookup_hits(norm_lcov, normalize_path(diff_path, root))
        covered = set()
        uncovered = set()
        if hits is not None:
            for start, end in ranges:
                for lineno in range(start, end + 1):
                    count = hits.get(lineno)
                    if count is None:
                        continue
                    if count > 0:
                        covered.add(lineno)
                    else:
                        uncovered.add(lineno)
        result[diff_path] = {"covered": covered, "uncovered": uncovered}
    return result


def format_lines(line_numbers):
    """Compact an iterable of line numbers into a human-readable string."""
    nums = sorted(line_numbers)
    if not nums:
        return ""
    out = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        out.append(f"{start}" if start == prev else f"{start}-{prev}")
        start = prev = n
    out.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ", ".join(out)


def run_git(args):
    """Run a git command and return stdout (raises on non-zero exit)."""
    return subprocess.run(
        ["git"] + args,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def git_root():
    return run_git(["rev-parse", "--show-toplevel"]).strip()


def get_changed_rs_ranges(base):
    """Return ``{filepath: [(start, end)]}`` for new/changed ``.rs`` lines.

    Rename-aware: ``--find-renames`` makes git emit a renamed file as a rename
    (its ``rename to`` path on the ``+++ b/`` side) carrying only the lines that
    genuinely changed, instead of ``--no-renames`` scoring the whole moved file
    as new. Without this, moving ``foo.rs`` to ``bar.rs`` re-exposes every
    already-merged (and possibly grandfathered-uncovered) line as a "changed"
    line, so a near-pure rename fails the gate on code that was never touched.
    ``--diff-filter=AMR`` must include ``R`` for the same reason: a detected
    rename has status ``R``, and an ``AM``-only filter would otherwise drop it
    entirely — under-counting the lines the rename genuinely added. Deletions
    (``D``) stay excluded; only the new side is ever scored.
    """
    merge_base = run_git(["merge-base", base, "HEAD"]).strip()
    diff = run_git(
        [
            "diff",
            "--unified=0",
            "--find-renames",
            "--diff-filter=AMR",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            merge_base,
            "HEAD",
            "--",
            "*.rs",
        ]
    )
    return parse_diff_hunks(diff)


def run_self_test():
    """Exercise the pure parsing/intersection logic against fixed data.

    No git, no filesystem: the functions under test are ``parse_lcov``,
    ``parse_diff_hunks`` and ``intersect``. One case covers a covered line and
    an uncovered line on the same changed file; another covers the docs-only
    (no changed lines) pass-through; a third checks that non-instrumentable
    changed lines (no ``DA:`` record) are ignored.
    """
    failures = 0

    def check(name, cond):
        nonlocal failures
        status = "PASS" if cond else "FAIL"
        if not cond:
            failures += 1
        print(f"  {status}: {name}")

    root = os.getcwd()

    # --- covered + uncovered changed lines, unchanged line ignored -------------
    lcov_text = (
        "SF:src/lib.rs\n"
        "DA:10,1\n"   # changed, covered
        "DA:11,0\n"   # changed, uncovered
        "DA:50,1\n"   # unchanged — must be ignored by the intersection
        "end_of_record\n"
    )
    diff_text = (
        "diff --git a/src/lib.rs b/src/lib.rs\n"
        "--- a/src/lib.rs\n"
        "+++ b/src/lib.rs\n"
        "@@ -5,2 +10,2 @@\n"
        "+covered_line\n"
        "+uncovered_line\n"
    )
    lcov_files = parse_lcov(lcov_text)
    diff_ranges = parse_diff_hunks(diff_text)
    per_file = intersect(lcov_files, diff_ranges, root)

    check("one changed file present", len(per_file) == 1)
    entry = next(iter(per_file.values())) if per_file else {"covered": set(), "uncovered": set()}
    check("covered == {10}", entry["covered"] == {10})
    check("uncovered == {11}", entry["uncovered"] == {11})
    check("unchanged line 50 ignored", 50 not in entry["covered"] and 50 not in entry["uncovered"])

    total_covered = sum(len(v["covered"]) for v in per_file.values())
    total_uncovered = sum(len(v["uncovered"]) for v in per_file.values())
    check("total covered == 1", total_covered == 1)
    check("total uncovered == 1", total_uncovered == 1)
    if total_covered + total_uncovered:
        pct = 100.0 * total_covered / (total_covered + total_uncovered)
        check("coverage ratio == 50%", abs(pct - 50.0) < 1e-9)

    # --- no changed .rs lines → zero instrumentable lines (docs-only PR) -------
    per_file_empty = intersect(lcov_files, {}, root)
    total_empty = sum(len(v["covered"]) + len(v["uncovered"]) for v in per_file_empty.values())
    check("no diff → 0 instrumentable lines", total_empty == 0)

    # --- non-instrumentable changed lines (no DA record) are ignored ----------
    diff_text2 = (
        "diff --git a/src/lib.rs b/src/lib.rs\n"
        "--- /dev/null\n"
        "+++ b/src/lib.rs\n"
        "@@ -0,0 +1,3 @@\n"
        "+// comment\n"
        "+// another comment\n"
        "+// third comment\n"
    )
    diff_ranges2 = parse_diff_hunks(diff_text2)
    check("new-file hunk parsed as lines 1-3", diff_ranges2.get("src/lib.rs") == [(1, 3)])
    per_file3 = intersect(lcov_files, diff_ranges2, root)
    total3 = sum(len(v["covered"]) + len(v["uncovered"]) for v in per_file3.values())
    check("non-instrumentable changed lines ignored", total3 == 0)

    # --- format_lines compaction ----------------------------------------------
    check("format_lines single", format_lines([7]) == "7")
    check("format_lines range", format_lines([7, 8, 9]) == "7-9")
    check("format_lines mixed", format_lines([1, 2, 5, 8, 9, 10]) == "1-2, 5, 8-10")

    # --- absolute SF: path normalized against a (fake) repo root -------------
    # os.path.relpath works on string paths; the root need not exist on disk.
    fake_root = "/abs/root/nora"
    lcov_abs = (
        "SF:/abs/root/nora/nora-registry/src/lib.rs\n"
        "DA:5,1\n"
        "end_of_record\n"
    )
    diff_abs = (
        "diff --git a/nora-registry/src/lib.rs b/nora-registry/src/lib.rs\n"
        "--- a/nora-registry/src/lib.rs\n"
        "+++ b/nora-registry/src/lib.rs\n"
        "@@ -0,0 +5,1 @@\n"
        "+new_line\n"
    )
    per_file_abs = intersect(parse_lcov(lcov_abs), parse_diff_hunks(diff_abs), fake_root)
    entry_abs = next(iter(per_file_abs.values())) if per_file_abs else {"covered": set(), "uncovered": set()}
    check("absolute SF path normalized + matched", entry_abs["covered"] == {5})

    # --- +++ /dev/null (deletion on the new side) is ignored -----------------
    diff_del = (
        "diff --git a/src/deleted.rs b/src/deleted.rs\n"
        "--- a/src/deleted.rs\n"
        "+++ /dev/null\n"
        "@@ -1,3 +0,0 @@\n"
        "-old\n"
        "-old\n"
        "-old\n"
    )
    check("deletion (new side /dev/null) ignored", not parse_diff_hunks(diff_del))

    # --- a rename (--find-renames) scores only the genuinely-changed lines -----
    # git emits a rename+modify with `rename from/to` headers and a hunk that
    # covers ONLY the changed lines, keyed by the new path on `+++ b/`. The
    # grandfathered, unchanged body of the moved file must NOT reappear as
    # "changed" (the bug that failed the gate on near-pure renames).
    diff_rename = (
        "diff --git a/src/storage/s3.rs b/src/storage/object.rs\n"
        "similarity index 88%\n"
        "rename from src/storage/s3.rs\n"
        "rename to src/storage/object.rs\n"
        "--- a/src/storage/s3.rs\n"
        "+++ b/src/storage/object.rs\n"
        "@@ -82,0 +83,3 @@ impl ObjectStorage {\n"
        "+    pub fn new_gcs() {}\n"
        "+    // added\n"
        "+    // added\n"
    )
    ranges_rename = parse_diff_hunks(diff_rename)
    check(
        "rename scores only changed lines under the new path",
        ranges_rename == {"src/storage/object.rs": [(83, 85)]},
    )
    check(
        "rename does not re-expose the old path",
        "src/storage/s3.rs" not in ranges_rename,
    )

    # --- malformed DA: lines are skipped --------------------------------------
    lcov_bad = (
        "SF:src/lib.rs\n"
        "DA:abc\n"
        "DA:1\n"
        "DA:5,1\n"
        "end_of_record\n"
    )
    check("malformed DA: lines skipped", parse_lcov(lcov_bad).get("src/lib.rs") == {5: 1})

    if failures:
        print(f"diff-coverage self-test: {failures} FAILURE(S).")
        return 1
    print("diff-coverage self-test: all PASS.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Diff-scoped coverage gate for pull requests.")
    parser.add_argument("--lcov", help="Path to an lcov.info file.")
    parser.add_argument("--base", help="PR base SHA (merge-base is computed from it).")
    parser.add_argument("--threshold", type=float, default=70.0, help="Minimum diff-scoped coverage %% (default 70).")
    parser.add_argument("--self-test", action="store_true", help="Run in-script unit tests and exit.")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if args.threshold < 0 or args.threshold > 100:
        parser.error("--threshold must be between 0 and 100")

    if not args.lcov:
        parser.error("--lcov is required (unless --self-test)")
    if not args.base:
        parser.error("--base is required (unless --self-test)")
    if not os.path.isfile(args.lcov):
        print(f"diff-coverage: lcov file not found: {args.lcov}", file=sys.stderr)
        return 2

    try:
        root = git_root()
        diff_ranges = get_changed_rs_ranges(args.base)
    except subprocess.CalledProcessError as e:
        print(f"diff-coverage: git command failed: {' '.join(e.cmd)}", file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"diff-coverage: required command not found: {e.filename}", file=sys.stderr)
        return 2

    try:
        with open(args.lcov, "r", encoding="utf-8", errors="replace") as fh:
            lcov_files = parse_lcov(fh.read())
    except OSError as e:
        print(f"diff-coverage: cannot read lcov file {args.lcov}: {e}", file=sys.stderr)
        return 2

    per_file = intersect(lcov_files, diff_ranges, root)

    total_covered = sum(len(v["covered"]) for v in per_file.values())
    total_uncovered = sum(len(v["uncovered"]) for v in per_file.values())
    total_instrumentable = total_covered + total_uncovered

    if total_instrumentable == 0:
        print(
            "diff-coverage: no changed instrumentable .rs lines — "
            "skipping (docs-only or non-instrumentable PR)."
        )
        return 0

    pct = 100.0 * total_covered / total_instrumentable
    print(
        f"diff-coverage: {total_covered}/{total_instrumentable} changed instrumentable "
        f".rs lines covered ({pct:.1f}%); threshold {args.threshold:g}%."
    )

    under = {f: v for f, v in per_file.items() if v["uncovered"]}
    if under:
        print("")
        print("Under-covered changed files:")
        for filepath in sorted(under):
            uncovered = under[filepath]["uncovered"]
            print(
                f"  {filepath}: {len(uncovered)} uncovered line(s): {format_lines(uncovered)}"
            )

    if pct < args.threshold:
        print("")
        print(f"diff-coverage: FAIL — {pct:.1f}% < {args.threshold:g}% threshold.")
        return 1
    print("")
    print("diff-coverage: PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
