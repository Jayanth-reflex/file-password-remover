#!/usr/bin/env bash
# Write SHA-256 sums for every release artifact, and verify them immediately.
#
# Verification is not decoration: it catches a truncated copy before the file
# is published, which is the only time it is cheap to catch.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p dist

if [ -z "$(ls -A dist 2>/dev/null | grep -v SHA256SUMS || true)" ]; then
  echo "dist/ is empty -- run 'make build' or 'make bundle' first" >&2
  exit 1
fi

cd dist
: > SHA256SUMS
for f in *; do
  [ "$f" = "SHA256SUMS" ] && continue
  # dist/ also holds the unpacked bundle directory; checksum the archives and
  # distributions, not the tree they were made from.
  [ -d "$f" ] && continue
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" >> SHA256SUMS
  else
    shasum -a 256 "$f" >> SHA256SUMS
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi

echo
echo "dist/SHA256SUMS:"
cat SHA256SUMS
