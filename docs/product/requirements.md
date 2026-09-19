# Product requirements

## What this is

A local tool that removes password protection from a file, for someone who
already has the password and wants an unlocked copy. Three shapes: a command
line, a small desktop window, and a Python API.

## Who it is for

- Someone with an archive of their own encrypted documents who wants to stop
  typing the same password.
- An administrator scripting a migration off a password-protected format.
- Anyone who was about to paste a confidential PDF into a website called
  something like "free-pdf-unlock.example" and should not.

That last one is the reason the tool is offline-only and the reason the README
leads with it.

## What it is not

Not a password recovery tool. Not a DRM remover. Not a converter. Not a
service. These are listed as non-goals rather than "future work" because they
are decisions, not gaps.

---

## Functional requirements

Each requirement has a test that enforces it; the third column names the file.

| # | Requirement | Verified by |
| --- | --- | --- |
| F-01 | Accept a file selected by the user and identify it **by content**, not extension | `tests/unit/test_detection.py::test_renaming_a_file_does_not_change_what_it_is` |
| F-02 | Report what protection a file carries **without** asking for a password | `tests/integration/test_cli.py::test_inspect_needs_no_password` |
| F-03 | Prompt for the password without echoing it and without argv exposure | `tests/integration/test_cli.py::test_password_on_argv_is_refused_with_a_reason` |
| F-04 | Validate the password with the format's own verifier before writing anything | `tests/integration/test_*.py::test_wrong_password_*` |
| F-05 | Remove protection only when technically possible **and** authorised | `tests/security/test_no_bypass.py` |
| F-06 | Preserve contents, structure, metadata and timestamps | `tests/integration/test_pdf.py::test_metadata_is_preserved`, `test_zip.py::test_metadata_is_preserved` |
| F-07 | Write a **new** file by default; never touch the source unless `--in-place` | `tests/integration/test_engine.py::test_in_place_replaces_the_source_only_when_asked` |
| F-08 | Never overwrite an existing output without `--overwrite` | `tests/integration/test_engine.py::test_existing_output_is_not_clobbered` |
| F-09 | Batch mode: process many files, report each one, never stop silently | `tests/integration/test_batch.py` |
| F-10 | Distinguish wrong password / corrupt / unsupported / unauthorised / not protected | `tests/integration/test_cli.py` exit-code tests |
| F-11 | Never report success unless the output has been re-read and verified | `tests/integration/test_pdf.py::test_verification_failure_discards_the_output` |
| F-12 | No backend, no upload, no telemetry | `tests/security/test_no_network.py` |
| F-13 | Delete temporary decrypted data after processing | `tests/unit/test_securefs.py`, `tests/security/test_no_leaks.py::test_no_plaintext_survives_a_failed_run` |
| F-14 | Never log passwords, file contents or sensitive metadata | `tests/unit/test_logging_redaction.py`, `tests/security/test_no_leaks.py` |
| F-15 | Clear progress, success, warning and error states | `tests/unit/test_output_rendering.py`, `tests/integration/test_gui.py` |
| F-16 | Accessible and localisation-ready interfaces | `tests/integration/test_gui.py` accessibility block, `tests/unit/test_i18n.py` |
| F-17 | Machine-readable output for scripting | `tests/integration/test_cli.py::test_*_json` |
| F-18 | Stable, documented exit codes | `fpr/errors.py::ExitCode`, `docs/ops/cli.md` |

## Non-functional requirements

| # | Requirement | Status |
| --- | --- | --- |
| N-01 | Offline by default and by construction | Enforced: no network import anywhere in the package |
| N-02 | Start-up under 1 s for `inspect` on a typical file | Met: `fpr inspect` on a 3-page PDF completes in well under a second |
| N-03 | Memory proportional to the largest *entry*, not the archive, for ZIP | Met (streamed); **not met for Office** — msoffcrypto decrypts in one buffer. Recorded in [known-limitations](../reports/known-limitations.md) |
| N-04 | Works without administrator rights | Met |
| N-05 | No runtime dependency on a system-wide Python for the desktop bundles | Met via PyInstaller |
| N-06 | Every dependency permissively licensed in the default install | Met; LGPL confined to an optional extra |

## Workflows

### Inspect → decide → remove (the default path)

1. The user points the tool at a file.
2. The tool identifies it and describes the protection **without a password**.
3. If the operation would not be permitted, it says so **now** — before asking
   for a secret. Being asked for a password and only then told "refused" is
   both annoying and a small privacy leak.
4. The user supplies the password.
5. The tool decrypts into a private temporary file, verifies it, and moves it
   into place atomically.
6. The report names the output, the protection removed, the algorithm, and the
   verification evidence.

### Batch

Same password, many files. Unprotected and unsupported files are **skipped**
(with a reason) rather than failed, because a real folder is mixed. Any genuine
failure makes the whole run exit `12`, so a script cannot mistake a partial run
for a complete one.

### Refusal

When the tool will not act, it says which rule applies, why, and what the user
could legitimately do instead — including "open it in the original application
and use its own Stop Protection command", which is often the right answer.

## Acceptance criteria for this release

1. Every format in the [matrix](format-matrix.md) marked *supported* has a
   generated fixture and a passing round-trip test.
2. A wrong password never produces an output file, on any format.
3. A verification failure never produces an output file.
4. `pytest`, `ruff`, `mypy --strict`, `bandit`, `pip-audit` all clean.
5. The CLI's exit codes are tested in a real child process.
6. The desktop window completes a removal under test, driven programmatically.
7. Every platform claim in the README is backed by an entry in the
   [verification report](../reports/verification-report.md) — including the
   ones that say "not built here".
