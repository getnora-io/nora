#!/usr/bin/env bash
# Regenerate readings.tsv: run readings.rb under three RubyGems and keep the union of their readings.
#   RubyGems 3.6.9 (ruby:3.4-slim), 4.0.20 (ruby:4.0-slim), and master at the revision the format page
#   pins (rubygems/rubygems 6db466b0012cfb7074a9398f0d4f63cbb39e7504), which has content addresses.
# Run from nora-registry/testdata/gems.
set -euo pipefail
rev=6db466b0012cfb7074a9398f0d4f63cbb39e7504
out=$(mktemp -d)
docker run --rm -v "$PWD:/w:ro" ruby:3.4-slim ruby -e 'require "rubygems/specification_policy"; load "/w/readings.rb"' > "$out/3.6.tsv"
docker run --rm -v "$PWD:/w:ro" ruby:4.0-slim ruby -e 'require "rubygems/specification_policy"; load "/w/readings.rb"' > "$out/4.0.tsv"
mkdir -p "$out/rg" && curl -sL "https://codeload.github.com/rubygems/rubygems/tar.gz/$rev" | tar -xz -C "$out/rg" --strip-components=1
docker run --rm -v "$PWD:/w:ro" -v "$out/rg:/rg:ro" ruby:3.4-slim ruby --disable-gems -I/rg/lib -e \
  'require "rubygems"; require "rubygems/specification_policy"; require "rubygems/content_address"; load "/w/readings.rb"' > "$out/master.tsv"
python3 - "$out" > readings.tsv <<'PY'
import sys
out = sys.argv[1]
heads, sets = [], []
for v in ("3.6", "4.0", "master"):
    d = {}
    for line in open(f"{out}/{v}.tsv", encoding="utf-8"):
        if line.startswith("#"):
            heads.append(line[2:].strip())
            continue
        stem, readings = line.rstrip("\n").split("\t")
        d[stem] = {r for r in readings.split(";") if r}
    sets.append(d)
print("# union of: " + " | ".join(heads))
for stem in sorted(sets[0]):
    print(stem + "\t" + ";".join(sorted(set().union(*(d[stem] for d in sets)))))
PY
