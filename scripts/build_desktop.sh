#!/usr/bin/env bash
# Build the standalone bundle (CLI + desktop app) for the current platform.
#
# The result is self-contained: it does not need a system Python. It is NOT
# signed -- signing and notarisation need identities this repository does not
# hold, and the steps are in docs/ops/release.md.
set -euo pipefail

cd "$(dirname "$0")/.."
VENV="${VENV:-.venv}"
PY="$VENV/bin/python"
[ -x "$PY" ] || PY="python3"

echo "==> toolchain"
"$PY" -V
"$PY" -m pip show pyinstaller >/dev/null 2>&1 || {
  echo "pyinstaller is not installed; run: pip install -e '.[build]'" >&2
  exit 1
}

echo "==> cleaning previous bundle"
rm -rf build/bundle dist/file-password-remover

echo "==> building"
"$PY" -m PyInstaller \
  --noconfirm \
  --clean \
  --distpath dist \
  --workpath build/bundle \
  packaging/pyinstaller/fpr.spec

BUNDLE="dist/file-password-remover"
case "$(uname -s)" in
  Darwin)  EXE="$BUNDLE/fpr" ;;
  Linux)   EXE="$BUNDLE/fpr" ;;
  MINGW*|MSYS*|CYGWIN*) EXE="$BUNDLE/fpr.exe" ;;
  *)       EXE="$BUNDLE/fpr" ;;
esac

echo "==> smoke testing the bundle"
"$EXE" version
"$EXE" formats >/dev/null

# A bundle that cannot actually decrypt anything is not a bundle. Generate a
# protected fixture with the *source* tree and process it with the *bundle*.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PYTHONPATH=src "$PY" - "$TMP" <<'PYEOF'
import sys
from pathlib import Path
from fpr.testing import fixtures as F

out = Path(sys.argv[1])
(out / "sample.pdf").write_bytes(
    F.make_pdf(F.PdfSpec(user="bundle-smoke-test", owner="bundle-owner"))
)
(out / "pw.txt").write_text("bundle-smoke-test")
(out / "pw.txt").chmod(0o600)
PYEOF

"$EXE" inspect "$TMP/sample.pdf"
"$EXE" remove "$TMP/sample.pdf" --password-file "$TMP/pw.txt"
test -f "$TMP/sample-unprotected.pdf" || { echo "bundle failed to write output" >&2; exit 1; }
# The path goes through argv, not through the source text. Under Git Bash on
# Windows, MSYS rewrites POSIX paths in *arguments* to native ones before
# handing them to a Windows binary, but leaves the inside of a -c string alone,
# so an interpolated "$TMP/..." reaches Python as an unusable /tmp/... path.
PYTHONPATH=src "$PY" - "$TMP/sample-unprotected.pdf" <<'PYEOF'
import sys

import pikepdf

with pikepdf.open(sys.argv[1]) as pdf:
    assert not pdf.is_encrypted, "bundle produced an encrypted file"
    assert len(pdf.pages) == 3, f"bundle lost pages: {len(pdf.pages)}"
print("bundle output verified independently: 3 pages, not encrypted")
PYEOF

echo
echo "==> bundle at $BUNDLE"
du -sh "$BUNDLE"
