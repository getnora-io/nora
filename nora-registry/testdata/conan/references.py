# Regenerate (from the repository root):
#   docker run --rm -v "$PWD/nora-registry/testdata/conan:/w:ro" python:3.13-slim sh -c 'pip install -q "conan==2.21.0" 2>/dev/null; python /w/references.py' > nora-registry/testdata/conan/references.tsv
# How Conan 2 reads a reference: RecipeReference.loads splits it, validate_ref checks it as
# `conan create`/`export` do (lowercase; with core:allow_uppercase_pkg_names the uppercase rule
# only warns), and Version gives the key versions compare equal by. One row per string:
# reference, name, version, user, channel (empty: none), validate_ref result (OK, UPPERCASE: only
# with the uppercase setting, or INVALID), version key (equal keys: equal versions). Unparsable:
# every field after the reference is LOADS-ERROR.
import itertools
from conan import __version__ as conan_version
from conan.api.model import RecipeReference
from conan.errors import ConanException

names = ["zlib", "openssl", "fmt", "pkg_a", "dots.and+plus", "a", "Zlib", "_lead", "-lead", "a" * 101,
         "a" * 102, "x/y", "n@m", "café", "1abc", "boost-ext"]
versions = ["1.2.13", "1.2.13.0", "1.2.13.00", "01.2.13", "1.2.013", "1.2", "1", "1.2.13-rc1",
            "1.2.13-RC1", "1.2.13+b1", "1.2.13-rc.1+build.7", "v1.2", "2024.01.01", "cci.20230101",
            "1.0.0-", "1.0.0+", "1..0", "system", "1.2.13_1", "7", "1.0+b+c"]
users = [None, ("acme", "stable"), ("_", "_"), ("Acme", "Stable"), ("my-user", "test.channel"), ("acme", None)]


def key(v):
    return repr((tuple(i.value for i in v._nonzero_items), key(v._pre) if v._pre else None,
                 key(v._build) if v._build else None))


refs = []
for n, v in itertools.product(names, versions[:4]):
    refs.append(f"{n}/{v}")
for v in versions:
    refs.append(f"zlib/{v}")
for uc in users:
    if uc is None:
        refs.append("zlib/1.2.13@")
    elif uc[1] is None:
        refs.append(f"zlib/1.2.13@{uc[0]}")
    else:
        refs.append(f"zlib/1.2.13@{uc[0]}/{uc[1]}")
refs += ["zlib", "zlib/", "/1.0", "zlib/1.2.13#abc", "zlib/1.2.13@acme/stable#abc%1700000000.0",
         "zlib/1.2.13:da39a3ee5e6b4b0d3255bfef95601890afd80709"]

print(f"# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/conan:/w:ro\" python:3.13-slim sh -c 'pip install -q \"conan=={conan_version}\" 2>/dev/null; python /w/references.py' > nora-registry/testdata/conan/references.tsv")
print(f"# Conan {conan_version} (python:3.13-slim)")
print("# reference\tname\tversion\tuser\tchannel\tvalidate_ref\tversion key")
seen = set()
for r in refs:
    if r in seen:
        continue
    seen.add(r)
    try:
        ref = RecipeReference.loads(r)
    except ConanException:
        print("\t".join([r] + ["LOADS-ERROR"] * 6))
        continue
    try:
        ref.validate_ref()
        result = "OK"
    except ConanException:
        try:
            ref.validate_ref(allow_uppercase=True)
            result = "UPPERCASE"
        except ConanException:
            result = "INVALID"
    print("\t".join([r, ref.name, str(ref.version), ref.user or "", ref.channel or "", result, key(ref.version)]))
