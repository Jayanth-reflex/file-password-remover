#!/usr/bin/env bash
# Run every quality gate and capture the output as release evidence.
#
# Each gate writes its own log under artifacts/verification/, and the exit
# status of each is recorded in summary.txt. The script does NOT stop at the
# first failure -- a verification report that omits the gates after the first
# red one is not a verification report.
set -uo pipefail

cd "$(dirname "$0")/.."
OUT="artifacts/verification"
rm -rf "$OUT"; mkdir -p "$OUT"
PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"
BIN="$(dirname "$PY")"

SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
overall=0

run() {
  local name="$1"; shift
  echo "==> $name"
  local log="$OUT/$name.log"
  {
    echo "\$ $*"
    echo
  } > "$log"
  "$@" >> "$log" 2>&1
  local code=$?
  printf '%-22s exit=%-3s %s\n' "$name" "$code" "$*" >> "$SUMMARY"
  [ "$code" -ne 0 ] && overall=1
  echo "    exit=$code  -> $log"
  return 0
}

{
  echo "File Password Remover -- verification run"
  echo "date        : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "host        : $(uname -srm)"
  echo "python      : $("$PY" -V 2>&1)"
  echo "commit      : $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repository')"
  echo
} | tee "$OUT/environment.txt"

run environment         "$PY" -c "import platform,sys;print(sys.version);print(platform.platform())"
run version             "$BIN/fpr" version
run ruff-check          "$BIN/ruff" check .
run ruff-format         "$BIN/ruff" format --check .
run mypy                "$BIN/mypy"
run pytest              "$PY" -m pytest -q --cov=fpr --cov=fpr_gui --cov-report=term --cov-report=xml:artifacts/coverage.xml
run pytest-slow         "$PY" -m pytest -q -m slow
run pytest-security     "$PY" -m pytest -q tests/security -v
run bandit              "$BIN/bandit" -q -c pyproject.toml -r src
run pip-audit           "$BIN/pip-audit" --progress-spinner off --skip-editable
run docs-links          "$PY" scripts/check_docs.py
run dependency-evidence "$PY" scripts/audit_dependencies.py
run upstream-repro      "$PY" scripts/repro_msoffcrypto_encrypt.py
run build-wheel         "$PY" -m build --outdir dist
run verify-install      bash scripts/verify_install.sh
run checksums           bash scripts/checksums.sh

echo
echo "==== summary ===="
cat "$SUMMARY"
if [ "$overall" -eq 0 ]; then
  echo "ALL GATES PASSED"
else
  echo "SOME GATES FAILED -- see $OUT"
fi
exit "$overall"
