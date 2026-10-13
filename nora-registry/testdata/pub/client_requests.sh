#!/bin/sh
# Regenerate (from the repository root):
#   docker run --rm -v "$PWD/nora-registry/testdata/pub:/w:ro" dart:stable sh /w/client_requests.sh > nora-registry/testdata/pub/client-requests.tsv
set -e
echo "# Regenerate: docker run --rm -v \"\$PWD/nora-registry/testdata/pub:/w:ro\" dart:stable sh /w/client_requests.sh > nora-registry/testdata/pub/client-requests.tsv"
dart run /w/client_requests.dart
