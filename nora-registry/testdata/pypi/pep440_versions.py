# Regenerate: docker run --rm -v "$PWD/nora-registry/testdata/pypi:/w:ro" python:3.13-slim python /w/pep440_versions.py > nora-registry/testdata/pypi/pep440-versions.tsv
# PEP 440 normal forms as packaging (vendored in pip) computes them: for each version string,
# str(Version(v)) and canonicalize_version(v) (trailing release zeros stripped), or INVALID.
# The strings combine every spelling the spec allows for each part, plus strings it refuses.
import itertools
import pip
from pip._vendor import packaging
from pip._vendor.packaging.version import Version, InvalidVersion
from pip._vendor.packaging.utils import canonicalize_version

epochs = ["", "1!", "0!", "01!"]
leads = ["", "v", "V"]
releases = ["1", "1.0", "1.0.0", "01.02", "0", "0.0", "1.2.3.4", "10.0.00", "2026.10.12"]
pres = ["", "a1", "a", ".a1", "-a1", "_a1", "alpha1", "ALPHA.1", "b2", "beta-2", "c3", "rc3",
        ".rc.3", "pre4", "preview4", "-rc", "RC_1", "a01"]
posts = ["", "-1", ".post1", "post1", "-post-1", "_post_1", ".post", "rev2", ".r3", "r", "POST1", "-01"]
devs = ["", ".dev0", "dev", "-dev1", "_dev_2", ".DEV3", "dev007"]
locals_ = ["", "+local", "+Local.7", "+abc-007_x", "+1.2", "+UBUNTU-1", "+0"]
invalid = ["1.", ".1", "1..0", "1.0-", "1.0+", "1.0+.a", "a1", "1.0abc", "1.0-beta-1", "2004b",
           "1.0.0-final", "1_0", "1.0+a..b", "1.0+-a", "!1.0", "1!", "v", "", "1.0.dev.1.2",
           "1.0a1a2", "1.0post1post2", "1.0-r", "1.0--1", "1.0.post-1", "1.0+a+b", " 1.0", "1.0 "]

def row(v):
    try:
        parsed = Version(v)
    except InvalidVersion:
        return f"{v}\tINVALID\tINVALID"
    return f"{v}\t{parsed}\t{canonicalize_version(v)}"

seen = set()
out = [f"# pip {pip.__version__}, packaging {packaging.__version__}"]
def add(v):
    if v not in seen and "\t" not in v and "\n" not in v:
        seen.add(v)
        out.append(row(v))
# every part varied alone around a plain release
for r in releases:
    for part in [epochs, leads, pres, posts, devs, locals_]:
        for p in part:
            if part is epochs:
                add(p + r)
            elif part is leads:
                add(p + r)
            else:
                add(r + p)
# combinations of all parts, sampled deterministically
for i, combo in enumerate(itertools.product(epochs, leads, releases, pres, posts, devs, locals_)):
    if i % 4001 == 0:
        e, l, r, pr, po, d, lo = combo
        add(l + e + r + pr + po + d + lo)
        add(e + r + pr + po + d + lo)
for v in invalid:
    add(v)
# A label's trailing separator with no number after it, and other shapes random strings found.
edges = ["7c.", "0c_", "1B.", "72A-", "7.42C-", "5A.", "2r_", "5AR-", "5cR.", "28a_", "1r-",
         "2C_+7PAt", "1.0a.post1", "1.0rc-", "1.0.dev_", "1.0post.", "1.0-r.dev", "1.0a_dev",
         "1.0.r.", "1.0-dev-", "1.0_post_", "v1.0b-", "1!1.0rc.", "1.0a.-1", "1.0a--1", "1.0a._1"]
for v in edges:
    add(v)
# Strings built from the grammar's own tokens, sampled with a fixed seed.
import random
rng = random.Random(440)
tokens = ["0", "1", "2", "9", "00", "07", "10", ".", ".", "-", "_", "+", "!", "a", "alpha", "b",
          "beta", "c", "rc", "pre", "preview", "post", "rev", "r", "dev", "v", "A", "RC", "Post",
          "DEV", "x", "local"]
for _ in range(400):
    add("".join(rng.choice(tokens) for _ in range(rng.randint(1, 8))))
print("\n".join(out))
