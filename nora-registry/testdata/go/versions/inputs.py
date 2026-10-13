# Version spellings for golang.org/x/mod (main.go). Regenerate the corpus:
#   python3 nora-registry/testdata/go/versions/inputs.py > /tmp/go-inputs.txt
#   docker run --rm -v "$PWD/nora-registry/testdata/go/versions:/w:ro" -v /tmp/go-inputs.txt:/in.txt:ro golang:1.25 \
#     sh -c 'cp -r /w /p && cd /p && go mod tidy >/dev/null 2>&1; go run . /in.txt' \
#     > nora-registry/testdata/go/versions/canonical.tsv
import itertools
import random

base = ["v1", "v1.2", "v1.2.3", "1.2.3", "v01.2.3", "v1.02.3", "v0.0.0", "V1.2.3", "v1.2.3.4", "v2.0.0"]
pre = ["", "-beta", "-Beta.1", "-0", "-01", "-20231012120000-abcdef123456", "-0.20231012120000-abcdef123456", "-", "-a..b"]
build = ["", "+incompatible", "+build", "+meta.1", "+"]
out = set(b + p + m for b, p, m in itertools.product(base, pre, build))
rng = random.Random(6)
tokens = ["v", "1", "2", "0", "01", ".", ".", "-", "+", "beta", "incompatible", "x"]
for _ in range(1500):
    out.add("".join(rng.choice(tokens) for _ in range(rng.randint(1, 8))))
print("\n".join(sorted(v for v in out if v and "\t" not in v)))
