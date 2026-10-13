#!/bin/sh
# Regenerate (from the repository root):
#   docker run --rm -v "$PWD/nora-registry/testdata/pub:/w:ro" dart:stable sh /w/versions.sh > nora-registry/testdata/pub/versions.tsv
set -e
mkdir -p /g/bin && cp /w/versions.dart /g/bin/
printf 'name: g\nenvironment: {sdk: ^3.0.0}\ndependencies: {pub_semver: 2.2.0}\n' > /g/pubspec.yaml
cd /g && dart pub get > /dev/null
echo "# Regenerate: docker run --rm -v \"\$PWD/nora-registry/testdata/pub:/w:ro\" dart:stable sh /w/versions.sh > nora-registry/testdata/pub/versions.tsv"
echo "# $(dart --version 2>&1), pub_semver $(awk '/^  pub_semver:/{f=1} f&&/^    version:/{gsub(/"/,"",$2);print $2;exit}' pubspec.lock)"
echo "# version<TAB>pub.dev canonical form (INVALID: pub_semver does not parse it)"
dart run bin/versions.dart
