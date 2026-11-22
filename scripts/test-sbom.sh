#!/usr/bin/env bash
# test-sbom.sh — self-test for scripts/sbom.py (#1313).
#
# The release job trusts `sbom.py check` to fail on an SBOM that does not describe the
# binary. A check that never fails looks exactly like one that passes, so this test
# generates the real SBOM for the release target and then breaks it in the ways the
# v1.4.7 file was broken (dev crates, files, no checksums, no licenses) plus the ways a
# generator bug could break it. Every broken file must fail the check; the untouched
# file and harmless rewrites (reordering, compact JSON) must pass.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SBOM="$ROOT/scripts/sbom.py"
TARGET="x86_64-unknown-linux-musl"
OTHER="aarch64-unknown-linux-musl"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

python3 "$SBOM" generate --target "$TARGET" --cdx "$TMP/base.cdx.json" --spdx "$TMP/base.spdx.json" \
  || { echo "FAIL: generate exited non-zero"; exit 1; }

# mutate <name> <cdx|spdx> <python statement over d>; writes $TMP/<name>.{cdx,spdx}.json
mutate() {
  local name="$1" which="$2" code="$3"
  cp "$TMP/base.cdx.json" "$TMP/$name.cdx.json"
  cp "$TMP/base.spdx.json" "$TMP/$name.spdx.json"
  python3 - "$TMP/$name.$which.json" "$code" <<'PY'
import json, sys
path, code = sys.argv[1], sys.argv[2]
d = json.load(open(path))
comps = d.get("components")
pkgs = d.get("packages")
def first(scope):
    return next(c for c in comps if c["scope"] == scope)
exec(code)
json.dump(d, open(path, "w"), indent=2)
PY
}

expect() {
  local want="$1" name="$2" target="${3:-$TARGET}"
  local out rc
  out="$(python3 "$SBOM" check --target "$target" --cdx "$TMP/$name.cdx.json" --spdx "$TMP/$name.spdx.json" 2>&1)"
  rc=$?
  if [ "$want" = pass ] && [ $rc -eq 0 ]; then echo "ok   pass: $name"
  elif [ "$want" = fail ] && [ $rc -eq 1 ]; then echo "ok   fail: $name — $(printf '%s\n' "$out" | sed -n 2p | sed 's/^ *//')"
  else
    echo "FAIL $name: expected $want, exit $rc"; printf '%s\n' "$out" | head -5
    FAILURES=$((FAILURES + 1))
  fi
}

# ── must pass ─────────────────────────────────────────────────────────────
expect pass base
mutate reordered cdx 'd["components"].reverse()'
python3 - "$TMP/reordered.spdx.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["packages"].reverse(); d["relationships"].reverse()
json.dump(d, open(sys.argv[1], "w"), separators=(",", ":"))
PY
expect pass reordered

# ── must fail: what syft put into the v1.4.7 SBOM ─────────────────────────
mutate dev-crate cdx 'c = dict(first("required")); c.update(name="criterion", version="0.8.2", purl="pkg:cargo/criterion@0.8.2", **{"bom-ref": "pkg:cargo/criterion@0.8.2"}); comps.append(c)'
expect fail dev-crate
mutate file-component cdx 'comps.append({"type": "file", "name": ".github/workflows/ci.yml"})'
expect fail file-component
mutate no-hash cdx 'first("required").pop("hashes")'
expect fail no-hash
mutate no-license spdx 'pkgs[1]["licenseDeclared"] = "NOASSERTION"'
expect fail no-license

# ── must fail: what a generator bug would do ──────────────────────────────
mutate missing-runtime cdx 'comps.remove(first("required"))'
expect fail missing-runtime
mutate missing-spdx spdx 'pkgs.pop()'
expect fail missing-spdx
mutate wrong-hash spdx 'pkgs[1]["checksums"][0]["checksumValue"] = "0" * 64'
expect fail wrong-hash
mutate build-as-runtime cdx 'first("excluded")["scope"] = "required"'
expect fail build-as-runtime
mutate runtime-as-build spdx '
root = next(r["relatedSpdxElement"] for r in d["relationships"] if r["relationshipType"] == "DESCRIBES")
r = next(r for r in d["relationships"] if r["relationshipType"] == "DEPENDS_ON")
r.update(spdxElementId=r["relatedSpdxElement"], relationshipType="BUILD_DEPENDENCY_OF", relatedSpdxElement=root)'
expect fail runtime-as-build
mutate duplicate cdx 'comps.append(dict(first("required")))'
expect fail duplicate
mutate other-version cdx 'd["metadata"]["component"]["version"] = "0.0.0"'
expect fail other-version

# ── must fail: ways around a check that reads only what it expects (review of #1314) ──
mutate nested-component cdx 'first("required")["components"] = [{"type": "library", "name": "criterion", "version": "0.8.2"}]'
expect fail nested-component
mutate spdx-id-reused spdx '
p = dict(pkgs[1]); p.update(name="criterion", versionInfo="0.8.2"); pkgs.insert(1, p)'
expect fail spdx-id-reused
mutate second-hash cdx 'first("required")["hashes"].insert(0, {"alg": "SHA-256", "content": "0" * 64})'
expect fail second-hash
mutate second-checksum spdx 'pkgs[1]["checksums"].insert(0, {"algorithm": "SHA256", "checksumValue": "0" * 64})'
expect fail second-checksum
mutate spdx-file spdx 'd["files"] = [{"SPDXID": "SPDXRef-File-ci", "fileName": ".github/workflows/ci.yml", "checksums": [{"algorithm": "SHA1", "checksumValue": "0" * 40}]}]'
expect fail spdx-file

# ── must fail: a package URL that names another version (scanners read the purl) ──
mutate purl-version cdx 'first("required")["purl"] = "pkg:cargo/" + first("required")["name"] + "@0.0.0"'
expect fail purl-version
mutate purl-version-spdx spdx 'pkgs[1]["externalRefs"][0]["referenceLocator"] = "pkg:cargo/" + pkgs[1]["name"] + "@0.0.0"'
expect fail purl-version-spdx
mutate purl-second-spdx spdx 'pkgs[1]["externalRefs"].append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/criterion@0.8.2"})'
expect fail purl-second-spdx

# ── the purl spec percent-encodes a version's build metadata: toml 1.1.4+spec-1.1.0 ──
python3 - "$TMP/base.cdx.json" "$TMP/base.spdx.json" <<'PY' || FAILURES=$((FAILURES + 1))
import json, sys
cdx, spdx = (json.load(open(p)) for p in sys.argv[1:])
plus = [c for c in cdx["components"] if "+" in c["version"]]
assert plus, "no crate with build metadata in the graph; pick another fixture"
for c in plus:
    want = "pkg:cargo/%s@%s" % (c["name"], c["version"].replace("+", "%2B"))
    assert c["purl"] == want and c["bom-ref"] == want, (c["purl"], want)
refs = [r["referenceLocator"] for p in spdx["packages"] for r in p.get("externalRefs", [])]
assert not any("+" in r for r in refs), [r for r in refs if "+" in r]
print("ok   purl: %d versions with build metadata percent-encoded" % len(plus))
PY
mutate purl-plus-raw cdx '
c = next(c for c in comps if "+" in c["version"])
c["purl"] = c["bom-ref"] = "pkg:cargo/%s@%s" % (c["name"], c["version"])'
expect fail purl-plus-raw

# ── must fail: an amd64 SBOM is not an arm64 SBOM ─────────────────────────
cp "$TMP/base.cdx.json" "$TMP/other-target.cdx.json"; cp "$TMP/base.spdx.json" "$TMP/other-target.spdx.json"
expect fail other-target "$OTHER"

echo
if [ "$FAILURES" -gt 0 ]; then
  echo "test-sbom: $FAILURES case(s) failed"
  exit 1
fi
echo "test-sbom: all cases behaved"
