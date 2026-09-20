# Verification report — 1.0.0

Every quality gate, the exact command that ran it, and its result. Reproduce
the whole thing with:

```bash
bash scripts/run_verification.sh
```

The script does **not** stop at the first failure — a report that omits the
gates after the first red one is not a report. Raw logs for every gate are
written to `artifacts/verification/`.

## Environment

| | |
| --- | --- |
| Date | 2026-09-19T15:40:26Z |
| Host | Darwin 27.0.0 arm64 (macOS 27, Apple silicon) |
| Python | 3.13.5 |
| fpr | 1.0.0 |
| pikepdf / libqpdf | 10.13.0.post1 / 12.3.2 |
| msoffcrypto-tool | 6.0.0 |
| pyzipper | 0.4.0 |
| py7zr (optional) | 1.1.3 |

## Results

| Gate | Command | Result |
| --- | --- | --- |
| Lint | `ruff check .` | **pass** — no findings |
| Format | `ruff format --check .` | **pass** — 98 files, including Python inside Markdown |
| Types | `mypy` (`--strict`, 29 files) | **pass** — no issues |
| Tests | `pytest -q --cov=fpr --cov=fpr_gui` | **pass** — **291 passed**, 88 % coverage |
| Performance | `pytest -q -m slow` | **pass** — 3 passed in 4.14 s |
| Security tests | `pytest -q tests/security -v` | **pass** — 46 passed |
| Static analysis | `bandit -c pyproject.toml -r src` | **pass** — **0 findings** (0 high, 0 medium, 0 low) |
| Dependency audit | `pip-audit` | **pass** — no known vulnerabilities |
| Advisory evidence | `python scripts/audit_dependencies.py` | **pass** — 0 OSV advisories across 9 pinned dependencies |
| Documentation links | `python scripts/check_docs.py` | **pass** — every relative link resolves |
| Upstream reproduction | `python scripts/repro_msoffcrypto_encrypt.py` | **pass** — the msoffcrypto encryptor bug reproduces; our writer round-trips |
| Wheel + sdist | `python -m build` | **pass** |
| Clean-environment install | `bash scripts/verify_install.sh` | **pass** — real removals inside a fresh venv |
| Checksums | `bash scripts/checksums.sh` | **pass** — written and verified |
| Desktop bundle | `bash scripts/build_desktop.sh` | **pass** — macOS arm64, smoke-tested end to end |

## Tests by area

| Area | Count | What it covers |
| --- | --- | --- |
| `tests/unit` | 127 | Secret handling, atomic writes and scrubbing, detection, policy, log redaction, the CFB writer, password routing, rendering, i18n |
| `tests/integration` | 115 | PDF, OOXML, ZIP, 7z and legacy Office end to end; engine behaviour; batch; the CLI in a real child process; the desktop window |
| `tests/security` | 46 | Leak tests, abuse cases, the no-network guarantee |
| `tests/perf` | 3 | Large PDF, 200 MiB archive, 100-file batch |
| **Total** | **291** | |

## Coverage

88 % of statements across `fpr` and `fpr_gui`. The notable figures, and why
they are what they are:

| Module | Coverage | Note |
| --- | --- | --- |
| `policy.py`, `errors.py`, `batch.py`, `logging_setup.py` | 100 % | The decision and error surfaces |
| `engine.py` | 99 % | The uncovered lines are the defensive wrapper around an unexpected adapter exception |
| `secret.py` | 95 % | |
| `cli/password_input.py` | 94 % | |
| `zipfiles.py` | 87 % | Uncovered: rare ZIP64 and malformed-extra branches |
| `pdf.py` | 82 % | Uncovered: raw-scan fallbacks for `/Encrypt` dictionaries our fixtures do not produce |
| `ooxml.py` | 77 % | Uncovered: the ECMA-376 *standard* (2007) branch, which has no fixture — [L-05](known-limitations.md) |
| `fpr_gui/app.py` | 74 % | Uncovered: file dialogs and the OS file-manager launch, which need a human or a mocked desktop |
| `legacy_office.py` | 60 % | Uncovered: the decryption branch, which has no fixture by construction — [L-04](known-limitations.md) |

No coverage threshold is enforced. A number that must be hit invites tests
written to hit it; the table above is more useful than a gate.

## What the format tests actually prove

| Format | Fixture written by | Read by | Independent? |
| --- | --- | --- | --- |
| OOXML agile | `fpr/testing/ooxml_agile.py` (ours, from [MS-OFFCRYPTO]) | msoffcrypto-tool | **Yes** |
| ZipCrypto | `fpr/testing/zipcrypto.py` (ours, from APPNOTE.TXT) | pyzipper, stdlib `zipfile` | **Yes** |
| CFB container | `fpr/testing/cfb.py` (ours) | olefile | **Yes** |
| ZIP AES | pyzipper | pyzipper | No — mitigated by per-entry SHA-256 comparison |
| PDF | pikepdf | pikepdf | No — mitigated by page-count and content-stream digest comparison ([R-12](../security/threat-model.md)) |
| 7z | py7zr | py7zr | No — same mitigation |
| Legacy Office | ours (File Information Block) | msoffcrypto-tool | Detection only |

## Artifacts produced

| Artifact | SHA-256 |
| --- | --- |
| `file_password_remover-1.0.0-py3-none-any.whl` | `7bc49555ab793d4b68ebae13242880a1ed3a5d48140d8c045b8a26bec47b88e3` |
| `file_password_remover-1.0.0.tar.gz` | `1fcf7ed1121e2ab5301ff58548a8de3970ae212a3b46f38adfd54ac527464dea` |

Plus, not checksummed because they are not release assets from this host:
`dist/file-password-remover/` (the macOS arm64 bundle, ~70 MiB),
`artifacts/gui-macos.png` and `artifacts/gui-macos-done.png` (desktop screenshots),
`artifacts/coverage.xml`, `artifacts/bandit.json`,
`docs/research/evidence/*.json`.

Checksums are regenerated by `scripts/checksums.sh` and will differ for any
later build — see [L-23](known-limitations.md) on reproducibility.

## Platforms

| Platform | Built | Tested | By |
| --- | --- | --- | --- |
| macOS 27 arm64 | **yes** | **yes** — full suite, bundle smoke test, GUI screenshot | this host |
| Linux x86-64 | in CI | in CI (`xvfb` for the GUI tests) | `.github/workflows/ci.yml` |
| Windows x86-64 | in CI | in CI | `.github/workflows/ci.yml` |
| iOS / Android | **no** | **no** | not shipped — [ADR-0010](../adr/0010-no-mobile-app-this-release.md) |

The CI workflows now run on GitHub on every push. Running them found a
Windows-only defect in `atomic_write` — `os.fsync` refuses a read-only
descriptor there, so every atomic write failed — that no run on this macOS host
could have surfaced. The Linux and Windows rows above are therefore backed by
executed jobs, not by a workflow file that merely parses. What is still *not*
covered: no human has driven the Linux or Windows desktop bundle by hand; CI
starts it, decrypts a fixture with it and reads the output back, which is a
smoke test rather than use.

## Failures encountered during the build

Twenty-two, all found by tests or by the build's own smoke checks, each with the
root cause and the fix recorded in
[docs/graph/node-ledger.md](../graph/node-ledger.md). The ones that changed a
design decision:

1. **msoffcrypto-tool 6.0.0's encryptor writes a malformed OLE container.**
   Led to writing our own CFB writer and ECMA-376 encryptor, which made the
   Office tests cross-implementation. Reproduction:
   `scripts/repro_msoffcrypto_encrypt.py`.
2. **`pikepdf.encryption.user_password` reports the supplied password**, not
   the document's. The restriction policy was built on a misreading of it;
   rewritten to use `user_password_matched` plus a separate empty-password open.
3. **PyInstaller's "Build complete!" preceded a binary that could not start.**
   The build script now runs the artifact and decrypts a real fixture with it.
4. **bandit found `explorer`/`xdg-open` invoked by bare name**, resolvable
   through a user-writable `PATH`. Fixed with absolute paths, not a suppression.

## Not verified

Stated so that nobody has to infer it:

- Linux and Windows bundles have not been run by a human.
- No bundle is signed or notarised.
- The desktop window has not been tested with VoiceOver, Narrator or Orca.
- ECMA-376 *standard* (Office 2007) encryption has no fixture.
- Legacy Office *decryption* has no fixture and is gated behind
  `--experimental`.
- Nothing has been tested against a real Microsoft Office or Adobe Acrobat
  installation; outputs are verified against the same open-source readers used
  to produce them, plus content invariants.
