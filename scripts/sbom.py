#!/usr/bin/env python3
"""Release SBOM built from the crate graph of one release target (#1313).

The release used to scan the checkout with syft. That listed what is in the
repository, not what is compiled into the binary: dev and test crates, crates
for other platforms, workflow files, and almost no checksums or licenses.

This script asks cargo's own resolver instead:

* runtime crates — ``cargo tree -e normal,no-proc-macro --target <triple>``:
  what is linked into ``nora``. CycloneDX scope ``required``.
* build-time crates — the rest of ``cargo tree -e normal,build``: proc macros,
  build scripts and their dependencies, compiled on the build host and not
  present in the binary. CycloneDX scope ``excluded``.
* checksums — the SHA-256 of each ``.crate`` file, from ``Cargo.lock``.
* licenses — the ``license`` field from ``cargo metadata``; the deprecated
  ``MIT/Apache-2.0`` form is written as ``MIT OR Apache-2.0``.

Usage::

    python3 scripts/sbom.py generate --target x86_64-unknown-linux-musl \\
        --cdx nora.cdx.json --spdx nora.spdx.json
    python3 scripts/sbom.py check --target x86_64-unknown-linux-musl \\
        --cdx nora.cdx.json --spdx nora.spdx.json

``check`` rebuilds the expected component list and fails when a file is
missing a crate, lists a crate that is not compiled for the target, carries a
checksum that differs from ``Cargo.lock``, has no license, or describes
another version or target. It then requires each file to be, up to the order
of lists, exactly the document ``generate`` writes for that graph and the
file's timestamp: anything else anywhere in it fails. The SPDX and CycloneDX
files are checked separately, so one cannot drift from the other.

Output is deterministic: timestamps come from ``SOURCE_DATE_EPOCH`` (the
release commit time if unset) and identifiers from the content.
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.parse
import uuid

PACKAGE = "nora-registry"
BINARY = "nora"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
REPO_URL = "https://github.com/getnora-io/nora"
TOOL = "nora scripts/sbom.py"
NS = uuid.UUID("5d0ea7e3-0f5a-4d0c-9a51-7d1c3c0b1313")

TREE_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+) v(?P<version>\S+)(?P<rest>.*)$")


def run(cmd, root):
    out = subprocess.run(cmd, cwd=root, check=True, capture_output=True, text=True)
    return out.stdout


def tree(root, target, edges):
    """Set of (name, version) cargo compiles for PACKAGE on target, root excluded."""
    text = run(
        ["cargo", "tree", "--locked", "-p", PACKAGE, "--target", target,
         "-e", edges, "--prefix", "none", "-f", "{p}"],
        root,
    )
    crates = set()
    for line in text.splitlines():
        m = TREE_LINE.match(line.strip())
        if not m:
            continue
        if m["name"] == PACKAGE:
            continue
        crates.add((m["name"], m["version"]))
    return crates


def lock_checksums(root):
    """(name, version) -> checksum for every crates.io package in Cargo.lock.

    Cargo.lock is TOML, but its [[package]] tables are flat key = "value" lines;
    reading them directly keeps the script on the Python of any runner (tomllib
    needs 3.11).
    """
    sums = {}
    with open(os.path.join(root, "Cargo.lock"), encoding="utf-8") as f:
        blocks = f.read().split("[[package]]")[1:]
    for block in blocks:
        fields = dict(re.findall(r'^(name|version|source|checksum) = "([^"]*)"$', block, re.M))
        if fields.get("source") == CRATES_IO and fields.get("checksum"):
            sums[(fields["name"], fields["version"])] = fields["checksum"]
    return sums


def normalize_license(expr):
    if not expr:
        return None
    parts = [p.strip() for p in expr.split("/")]
    return " OR ".join(p for p in parts if p) if len(parts) > 1 else expr.strip()


def metadata(root, target):
    data = json.loads(run(
        ["cargo", "metadata", "--locked", "--format-version", "1",
         "--filter-platform", target],
        root,
    ))
    info = {}
    version = None
    for p in data["packages"]:
        info[(p["name"], p["version"])] = {
            "license": normalize_license(p.get("license")),
            "source": p.get("source"),
            "description": (p.get("description") or "").strip(),
        }
        if p["name"] == PACKAGE and p.get("source") is None:
            version = p["version"]
    if version is None:
        raise SystemExit(f"{PACKAGE} is not a workspace member")
    return info, version


def expected(root, target):
    """PACKAGE version and what its SBOM must contain: {(name, version): {...}}."""
    runtime = tree(root, target, "normal,no-proc-macro")
    compiled = tree(root, target, "normal,build")
    missing = runtime - compiled
    if missing:
        raise SystemExit(f"runtime crates outside the build graph: {sorted(missing)}")
    sums = lock_checksums(root)
    meta, version = metadata(root, target)
    out = {}
    problems = []
    for key in sorted(compiled):
        m = meta.get(key)
        if m is None:
            problems.append(f"{key[0]} {key[1]}: not in cargo metadata")
            continue
        if m["source"] != CRATES_IO:
            problems.append(f"{key[0]} {key[1]}: source {m['source']!r} is not crates.io")
            continue
        if key not in sums:
            problems.append(f"{key[0]} {key[1]}: no checksum in Cargo.lock")
            continue
        if not m["license"]:
            problems.append(f"{key[0]} {key[1]}: no license in the crate metadata")
            continue
        out[key] = {
            "scope": "required" if key in runtime else "excluded",
            "sha256": sums[key],
            "license": m["license"],
            "description": m["description"],
        }
    if problems:
        raise SystemExit("cannot describe every crate:\n  " + "\n  ".join(problems))
    return version, out


def timestamp(root):
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        epoch = run(["git", "log", "-1", "--format=%ct"], root).strip()
    t = datetime.datetime.fromtimestamp(int(epoch), tz=datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def purl(name, version):
    """Package URL of a crate. The purl spec percent-encodes every character of the version
    outside A-Z a-z 0-9 . - _ ~, so build metadata reads `1.1.4%2Bspec-1.1.0`."""
    return f"pkg:cargo/{name}@{urllib.parse.quote(str(version), safe='.-_~')}"


def cyclonedx(version, target, comps, ts):
    components = []
    for (name, ver), c in comps.items():
        item = {
            "type": "library",
            "bom-ref": purl(name, ver),
            "name": name,
            "version": ver,
            "scope": c["scope"],
            "hashes": [{"alg": "SHA-256", "content": c["sha256"]}],
            "licenses": [{"expression": c["license"]}],
            "purl": purl(name, ver),
            "externalReferences": [{
                "type": "distribution",
                "url": f"https://crates.io/api/v1/crates/{name}/{ver}/download",
            }],
        }
        if c["description"]:
            item["description"] = c["description"]
        components.append(item)
    root_ref = purl(PACKAGE, version)
    body = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": {"components": [{"type": "application", "name": TOOL}]},
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": BINARY,
                "version": version,
                "licenses": [{"expression": "MIT"}],
                "purl": root_ref,
                "externalReferences": [{"type": "vcs", "url": REPO_URL}],
            },
            "properties": [{"name": "nora:target", "value": target}],
        },
        "components": components,
        "dependencies": [{
            "ref": root_ref,
            "dependsOn": [purl(n, v) for (n, v), c in comps.items()
                          if c["scope"] == "required"],
        }],
    }
    serial = uuid.uuid5(NS, json.dumps(body, sort_keys=True))
    return {"bomFormat": body.pop("bomFormat"), "specVersion": body.pop("specVersion"),
            "serialNumber": f"urn:uuid:{serial}", **body}


def spdx_id(name, version):
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", f"{name}-{version}")


def spdx(version, target, comps, ts):
    root_id = spdx_id(PACKAGE, version)
    packages = [{
        "SPDXID": root_id,
        "name": BINARY,
        "versionInfo": version,
        "downloadLocation": f"{REPO_URL}/releases/tag/v{version}",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "comment": f"nora binary for {target}",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                          "referenceType": "purl",
                          "referenceLocator": purl(PACKAGE, version)}],
    }]
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": root_id}]
    for (name, ver), c in comps.items():
        pid = spdx_id(name, ver)
        packages.append({
            "SPDXID": pid,
            "name": name,
            "versionInfo": ver,
            "downloadLocation": f"https://crates.io/api/v1/crates/{name}/{ver}/download",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": c["sha256"]}],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": c["license"],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl",
                              "referenceLocator": purl(name, ver)}],
        })
        if c["scope"] == "required":
            rels.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON",
                         "relatedSpdxElement": pid})
        else:
            rels.append({"spdxElementId": pid, "relationshipType": "BUILD_DEPENDENCY_OF",
                         "relatedSpdxElement": root_id})
    body = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{BINARY}-{version}-{target}",
        "creationInfo": {"created": ts, "creators": [f"Tool: {TOOL}"]},
        "packages": packages,
        "relationships": rels,
    }
    ns = uuid.uuid5(NS, json.dumps(body, sort_keys=True))
    body["documentNamespace"] = f"{REPO_URL}/sbom/{BINARY}-{version}-{target}-{ns}"
    return body


def write(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def one_per_kind(entries, kind_field, value_field, label, errs):
    """{algorithm: value}; a second entry for one algorithm is an error, not an override."""
    out = {}
    for e in entries:
        kind = e.get(kind_field)
        if kind in out:
            errs.append(f"{label} has more than one {kind} checksum")
        out[kind] = e.get(value_field)
    return out


def read_cdx(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    errs = []
    if d.get("bomFormat") != "CycloneDX":
        errs.append("not a CycloneDX document")
    meta = d.get("metadata", {})
    comp = meta.get("component", {})
    if comp.get("components"):
        errs.append("the described binary nests other components")
    root_purl = purl(PACKAGE, comp.get("version"))
    if comp.get("purl") != root_purl or comp.get("bom-ref") != root_purl:
        errs.append(f"the described binary has purl {comp.get('purl')!r}, expected {root_purl!r}")
    props = {p.get("name"): p.get("value") for p in meta.get("properties", [])}
    got = {}
    for c in d.get("components", []):
        key = (c.get("name"), c.get("version"))
        if c.get("type") != "library":
            errs.append(f"component {key[0]} {key[1]} has type {c.get('type')!r}, expected 'library'")
            continue
        if key in got:
            errs.append(f"component {key[0]} {key[1]} is listed twice")
        if c.get("components"):
            errs.append(f"component {key[0]} {key[1]} nests other components")
        if c.get("purl") != purl(*key) or c.get("bom-ref") != purl(*key):
            errs.append(f"component {key[0]} {key[1]} has purl {c.get('purl')!r}, "
                        f"expected {purl(*key)!r}")
        hashes = one_per_kind(c.get("hashes", []), "alg", "content",
                              f"component {key[0]} {key[1]}", errs)
        lic = [l.get("expression") or (l.get("license") or {}).get("id")
               for l in c.get("licenses", [])]
        got[key] = {"scope": c.get("scope"), "sha256": hashes.get("SHA-256"),
                    "license": lic[0] if len(lic) == 1 else None}
    return comp.get("name"), comp.get("version"), props.get("nora:target"), got, errs


def read_spdx(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    errs = []
    if d.get("spdxVersion") != "SPDX-2.3":
        errs.append("not an SPDX 2.3 document")
    for kind in ("files", "snippets"):
        if d.get(kind):
            errs.append(f"the document lists {kind}; only packages are expected")
    by_id = {}
    for p in d.get("packages", []):
        if p.get("SPDXID") in by_id:
            errs.append(f"SPDXID {p.get('SPDXID')} is used by more than one package")
        by_id[p.get("SPDXID")] = p
    described = [r["relatedSpdxElement"] for r in d.get("relationships", [])
                 if r.get("spdxElementId") == "SPDXRef-DOCUMENT"
                 and r.get("relationshipType") == "DESCRIBES"]
    if len(described) != 1 or described[0] not in by_id:
        return None, None, None, {}, errs + ["the document must describe exactly one package"]
    root_id = described[0]
    root = by_id[root_id]
    root_purls = [r.get("referenceLocator") for r in root.get("externalRefs", [])
                  if r.get("referenceType") == "purl"]
    if root_purls != [purl(PACKAGE, root.get("versionInfo"))]:
        errs.append(f"the described package has purls {root_purls!r}, "
                    f"expected [{purl(PACKAGE, root.get('versionInfo'))!r}]")
    runtime_ids = {r["relatedSpdxElement"] for r in d.get("relationships", [])
                   if r.get("spdxElementId") == root_id and r.get("relationshipType") == "DEPENDS_ON"}
    build_ids = {r["spdxElementId"] for r in d.get("relationships", [])
                 if r.get("relatedSpdxElement") == root_id
                 and r.get("relationshipType") == "BUILD_DEPENDENCY_OF"}
    target = (root.get("comment") or "").rsplit(" ", 1)[-1]
    got = {}
    for pid, p in by_id.items():
        if pid == root_id:
            continue
        key = (p.get("name"), p.get("versionInfo"))
        if key in got:
            errs.append(f"package {key[0]} {key[1]} is listed twice")
        sums = one_per_kind(p.get("checksums", []), "algorithm", "checksumValue",
                            f"package {key[0]} {key[1]}", errs)
        purls = [r.get("referenceLocator") for r in p.get("externalRefs", [])
                 if r.get("referenceType") == "purl"]
        if purls != [purl(*key)]:
            errs.append(f"package {key[0]} {key[1]} has purls {purls!r}, expected [{purl(*key)!r}]")
        if pid in runtime_ids and pid in build_ids:
            scope = "both"
        elif pid in runtime_ids:
            scope = "required"
        elif pid in build_ids:
            scope = "excluded"
        else:
            scope = None
        lic = p.get("licenseDeclared")
        got[key] = {"scope": scope, "sha256": sums.get("SHA256"),
                    "license": None if lic in (None, "", "NOASSERTION", "NONE") else lic}
    return root.get("name"), root.get("versionInfo"), target, got, errs


def compare(label, want_version, want_target, want, doc):
    name, version, target, got, errs = doc
    errs = [f"{label}: {e}" for e in errs]
    if name != BINARY:
        errs.append(f"{label}: describes {name!r}, expected {BINARY!r}")
    if version != want_version:
        errs.append(f"{label}: version {version!r}, expected {want_version!r}")
    if target != want_target:
        errs.append(f"{label}: target {target!r}, expected {want_target!r}")
    for key in sorted(set(want) - set(got)):
        errs.append(f"{label}: missing {key[0]} {key[1]} ({want[key]['scope']})")
    for key in sorted(set(got) - set(want)):
        errs.append(f"{label}: {key[0]} {key[1]} is not compiled for {want_target}")
    for key in sorted(set(want) & set(got)):
        w, g = want[key], got[key]
        for field in ("scope", "sha256", "license"):
            if g[field] != w[field]:
                errs.append(f"{label}: {key[0]} {key[1]} {field} is {g[field]!r}, "
                            f"expected {w[field]!r}")
    return errs


def canonical(value):
    """The document with every list sorted, so order carries no meaning but nothing else is lost."""
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [canonical(v) for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True))
    return value


def first_difference(got, want, path="$"):
    """Where two canonical documents part, as a JSON path, or None when they are equal."""
    if type(got) is not type(want):
        return f"{path}: {type(got).__name__} where {type(want).__name__} is expected"
    if isinstance(want, dict):
        for k in sorted(set(got) | set(want)):
            if k not in want:
                return f"{path}.{k}: not written by the generator"
            if k not in got:
                return f"{path}.{k}: missing"
            d = first_difference(got[k], want[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(want, list):
        if len(got) != len(want):
            return f"{path}: {len(got)} entries, {len(want)} expected"
        for i, (g, w) in enumerate(zip(got, want)):
            d = first_difference(g, w, f"{path}[{i}]")
            if d:
                return d
        return None
    return None if got == want else f"{path}: {got!r}, expected {want!r}"


def exact(label, path, generated):
    """The allowlist: the file must be, up to list order, the document the generator writes for
    this crate graph and the file's own timestamp. Field-by-field checks above say what is wrong
    in words; this one refuses anything they do not know about."""
    with open(path, encoding="utf-8") as f:
        d = first_difference(canonical(json.load(f)), canonical(generated))
    return [f"{label}: {d}"] if d else []


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mode", choices=["generate", "check"])
    ap.add_argument("--target", required=True)
    ap.add_argument("--cdx", required=True)
    ap.add_argument("--spdx", required=True)
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root)
    version, want = expected(root, a.target)

    if a.mode == "generate":
        ts = timestamp(root)
        write(a.cdx, cyclonedx(version, a.target, want, ts))
        write(a.spdx, spdx(version, a.target, want, ts))
        runtime = sum(1 for c in want.values() if c["scope"] == "required")
        print(f"SBOM {a.target}: {runtime} runtime crates, {len(want) - runtime} build-time crates")
        return 0

    errs = compare(a.cdx, version, a.target, want, read_cdx(a.cdx))
    errs += compare(a.spdx, version, a.target, want, read_spdx(a.spdx))
    if not errs:
        with open(a.cdx, encoding="utf-8") as f:
            cdx_ts = json.load(f).get("metadata", {}).get("timestamp")
        with open(a.spdx, encoding="utf-8") as f:
            spdx_ts = json.load(f).get("creationInfo", {}).get("created")
        errs += exact(a.cdx, a.cdx, cyclonedx(version, a.target, want, cdx_ts))
        errs += exact(a.spdx, a.spdx, spdx(version, a.target, want, spdx_ts))
    if errs:
        print(f"SBOM check FAILED for {a.target} ({len(errs)} problems):")
        for e in errs[:200]:
            print(f"  {e}")
        return 1
    runtime = sum(1 for c in want.values() if c["scope"] == "required")
    print(f"SBOM check OK for {a.target}: {runtime} runtime + {len(want) - runtime} "
          f"build-time crates, checksums match Cargo.lock, every crate has a license")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
