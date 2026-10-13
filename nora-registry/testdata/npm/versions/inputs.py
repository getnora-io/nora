# Version spellings for npm's semver.clean (clean.js). Regenerate the corpus:
#   python3 nora-registry/testdata/npm/versions/inputs.py > /tmp/npm-inputs.txt
#   docker run --rm -v "$PWD/nora-registry/testdata/npm/versions:/w:ro" -v /tmp/npm-inputs.txt:/in.txt:ro \
#     node:22-slim node /w/clean.js /in.txt > nora-registry/testdata/npm/versions/clean.tsv
import itertools
import random

base = ["1.2.3", "0.0.0", "10.20.30", "01.2.3", "1.2", "1.2.3.4", "9007199254740991.0.0", "9007199254740992.0.0"]
pre = ["", "-alpha", "-Alpha.1", "-beta.01", "-0", "-00", "-a-b", "-", "--", "-x..y", "-rc.1"]
build = ["", "+build", "+Build.5", "+", "+a..b"]
lead = ["", "v", "=", "=v", "V", " ", "vv"]
out = set(l + b + p + m for l, b, p, m in itertools.product(lead, base, pre, build))
rng = random.Random(5)
tokens = ["0", "1", "2", "01", "10", ".", ".", "-", "+", "=", "v", "V", "beta", "Beta", "rc", "x", " "]
for _ in range(1500):
    out.add("".join(rng.choice(tokens) for _ in range(rng.randint(1, 8))))
# Around node-semver's 256-character limit.
for n in (240, 250, 251, 252, 260):
    out.add("1.2.3-" + "a" * n)
    out.add("1.2.3+" + "b" * n)
print("\n".join(sorted(v for v in out if v and "\t" not in v and "\n" not in v)))
