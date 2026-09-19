#!/usr/bin/env bash
# Install the built wheel into a clean virtualenv and prove it works there.
#
# Building a wheel is not evidence that it installs; installing it is not
# evidence that it runs. This does both, in an environment that has never seen
# the source tree.
set -euo pipefail

cd "$(dirname "$0")/.."
WHEEL="$(ls -1 dist/*.whl 2>/dev/null | head -1 || true)"
[ -n "$WHEEL" ] || { echo "no wheel in dist/ -- run 'make build' first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "==> clean venv in $TMP"
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/python" -m pip install --quiet --upgrade pip
echo "==> installing $WHEEL"
"$TMP/venv/bin/python" -m pip install --quiet "$WHEEL"

echo "==> console scripts present"
test -x "$TMP/venv/bin/fpr"     || { echo "fpr entry point missing" >&2; exit 1; }
test -x "$TMP/venv/bin/fpr-gui" || { echo "fpr-gui entry point missing" >&2; exit 1; }

echo "==> version and formats"
"$TMP/venv/bin/fpr" version
"$TMP/venv/bin/fpr" formats > /dev/null

echo "==> optional extra is genuinely absent by default"
if "$TMP/venv/bin/python" -c "import py7zr" 2>/dev/null; then
  echo "py7zr was installed by the default wheel -- it must be an extra" >&2
  exit 1
fi
"$TMP/venv/bin/fpr" formats | grep -q "7z" && echo "   (7z row still listed: registry degrades, adapter absent)"

echo "==> end-to-end on a generated fixture"
WORK="$TMP/work"; mkdir -p "$WORK"
"$TMP/venv/bin/python" - "$WORK" <<'PYEOF'
import sys
from pathlib import Path
from fpr.testing import fixtures as F

out = Path(sys.argv[1])
(out / "sample.pdf").write_bytes(F.make_pdf(F.PdfSpec(user="install-check", owner="install-owner")))
(out / "sample.docx").write_bytes(F.make_encrypted_ooxml(F.make_docx()))
(out / "sample.zip").write_bytes(F.make_zip_aes(password="install-check"))
pw = out / "pw.txt"
pw.write_text("install-check")
pw.chmod(0o600)
PYEOF

"$TMP/venv/bin/fpr" remove "$WORK/sample.pdf" --password-file "$WORK/pw.txt"
"$TMP/venv/bin/fpr" remove "$WORK/sample.zip" --password-file "$WORK/pw.txt"
printf '%s' "correct horse battery staple" | "$TMP/venv/bin/fpr" remove "$WORK/sample.docx" --password-stdin

for f in sample-unprotected.pdf sample-unprotected.zip sample-unprotected.docx; do
  test -f "$WORK/$f" || { echo "missing output $f" >&2; exit 1; }
done

echo "==> wrong password still exits 3"
echo -n "definitely-wrong" > "$WORK/bad.txt"
set +e
"$TMP/venv/bin/fpr" remove "$WORK/sample.pdf" --password-file "$WORK/bad.txt" -o "$WORK/should-not-exist.pdf" >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 3 ] || { echo "expected exit 3, got $code" >&2; exit 1; }
[ ! -f "$WORK/should-not-exist.pdf" ] || { echo "an output was written for a wrong password" >&2; exit 1; }

echo
echo "install verification passed"
