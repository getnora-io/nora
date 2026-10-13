# Version strings for NuGet.Versioning to normalize (Program.cs). Regenerate the corpus:
#   python3 nora-registry/testdata/nuget/versions/inputs.py > /tmp/inputs.txt
#   docker run --rm -v "$PWD/nora-registry/testdata/nuget/versions:/w:ro" -v /tmp/inputs.txt:/in.txt:ro \
#     mcr.microsoft.com/dotnet/sdk:9.0 sh -c 'cp -r /w /p && cd /p && dotnet run --project nugetv.csproj -- /in.txt' \
#     > nora-registry/testdata/nuget/versions/normal-forms.tsv
import itertools
import random

base = ["1", "1.0", "1.0.0", "1.0.0.0", "1.0.0.1", "01.02.03", "1.00", "10.0.0.00", "0.0.0.0", "1.2.3.4",
        "1.2.3.4.5", "v1.0", "V1.0.0", " 1.0", "1.0 "]
pre = ["", "-beta", "-Beta", "-BETA.1", "-beta.01", "-rc.1", "-alpha-1", "-0", "-00", "-a.b.c", "-",
       "-beta..1", "-beta_1", "-beta+", "-1.2"]
meta = ["", "+build", "+Build.5", "+a.b", "+", "+build+again"]
out = set(b + p + m for b, p, m in itertools.product(base, pre, meta))
rng = random.Random(4)
tokens = ["0", "1", "2", "01", "10", ".", ".", "-", "+", "beta", "Beta", "rc", "alpha", "a", "x", " "]
for _ in range(3000):
    out.add("".join(rng.choice(tokens) for _ in range(rng.randint(1, 7))))
print("\n".join(sorted(v for v in out if "\t" not in v and "\n" not in v)))
