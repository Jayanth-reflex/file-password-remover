# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-09-25

Protection in both directions, on two more platforms, behind one visual
identity.

### Added

**Interfaces**
- `fpr protect`: write a verified, password-protected copy of a PDF or a ZIP,
  with a password you supply or one generated for you (`--generate`,
  `--password-out`). There is deliberately no `--in-place`.
- A generated-password mode built so that losing the only copy of a password is
  hard to do by accident: the password is surfaced only after the encrypted file
  exists, batches are refused, and `--json` returns it so an agent cannot
  destroy the file it just created.
- A menu: run `fpr` with no command and it prints every command, what it does,
  and what it does to your files, instead of an argparse dump. The effect of
  each command is written in words as well as carried in colour, so it reads
  the same in a CI log and to a screen reader.
- Virtual-terminal sequences are enabled on Windows, so the same colour that
  macOS and Linux terminals show also appears in `cmd.exe` and PowerShell.

**Platforms**
- An iOS app and an Android app over Swift and Kotlin ports of the engine,
  verified against the same cross-language test-vector corpus as the Python
  implementation, plus an interop check that opens their output with Python.
- A visual identity — hallmarking, not padlocks — shared by the CLI, the
  desktop window and both apps, with a maker's-mark icon.

**Project**
- An end-to-end suite that drives the installed executable as a subprocess
  through complete journeys, run on Linux, macOS and Windows in CI.
- A version-consistency test: one number, declared in every platform's own file
  format, checked in one place.

### Known limitations

`protect` covers PDF and ZIP only; the other adapters refuse rather than
silently writing an unencrypted copy. 7-Zip is unsupported on iOS. iOS writes
AES-128 for PDFs where the CLI and Android write AES-256, and says so in the
hallmark row. Neither app is store-distributed
([ADR-0011](docs/adr/0011-ship-mobile-apps-verified-not-published.md)).
`--password-out` is owner-only on macOS and Linux; on Windows it inherits the
directory's permissions.

## [1.0.0] — 2026-09-20

First release.

### Added

**Core**
- Local removal of password protection with post-write verification: an output
  is published only after it has been re-read from disk and proved to be
  readable and unprotected.
- Atomic output via a `0600` temp file in the destination's own directory and
  `os.replace`; the source is never modified unless `--in-place` is given.
- A password container that holds a wipeable buffer, refuses to be pickled,
  copied, formatted or logged, and zeroes itself when the operation ends.
- A policy layer (R1–R5) enforced before a password is requested and again at
  the point of decryption.

**Formats**
- PDF: standard security handler R2–R6 (RC4-40, RC4-128, AES-128, AES-256).
- Office Open XML: ECMA-376 agile and standard encryption.
- ZIP: WinZip AES-128/192/256 and legacy ZipCrypto.
- 7-Zip: AES-256 including encrypted headers, as an optional extra.
- Legacy Office 97–2003: detection supported; decryption experimental and
  gated behind `--experimental`.

**Interfaces**
- `fpr` CLI with `inspect`, `remove`, `formats` and `version`; JSON output;
  batch mode with per-item reporting; stable documented exit codes.
- Password input via fd, stdin, file, environment or prompt. `--password VALUE`
  is refused with an explanation.
- `fpr-gui`, a Tkinter desktop window over the same engine.
- A documented Python API (`fpr.inspect`, `fpr.remove`).

**Distribution**
- Container image published to GitHub Container Registry, built for amd64 and
  arm64, running as a non-root user and signed with cosign keyless signing. The
  publish workflow decrypts a PDF, a DOCX and a ZIP *inside the image* and
  checks that a wrong password still exits 3 before anything is pushed.
- Standalone macOS, Linux and Windows bundles built by CI, each smoke-tested by
  decrypting a generated fixture with the frozen binary.

**Project**
- Threat model, abuse-case analysis, security design and privacy statement.
- Ten architecture decision records.
- Open-source landscape survey and a dependency licence/advisory analysis
  backed by machine-readable evidence.
- Fixture generators written from the specifications — a CFB/OLE writer, an
  ECMA-376 agile encryptor and a ZipCrypto writer — so the Office and ZIP tests
  are cross-implementation rather than round trips.
- 291 automated tests; ruff, mypy `--strict`, bandit, pip-audit and gitleaks in
  CI.

### Known limitations

See [docs/reports/known-limitations.md](docs/reports/known-limitations.md). The
headlines: no mobile application ships in this release
([ADR-0010](docs/adr/0010-no-mobile-app-this-release.md)); Office decryption
buffers the whole package in memory; and temp-file scrubbing cannot guarantee
erasure on modern storage.

### Security

- No network code in the package, enforced by a test.
- No telemetry, crash reporting or update check.
- Zero findings from bandit; zero known advisories in any pinned dependency as
  of 2026-09-19.

[1.1.0]: https://github.com/Jayanth-reflex/file-password-remover/releases/tag/v1.1.0
[1.0.0]: https://github.com/Jayanth-reflex/file-password-remover/releases/tag/v1.0.0
