<div align="center">

<img src="docs/assets/desktop-verified.png" alt="The desktop app after unlocking a 12-page PDF, showing the hallmark row: encrypted false, pages 12, content digest and scope" width="720">

# File Password Remover

**Remove or add password protection on files you own — locally, with the result verified before it is written.**

[![CI](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/ci.yml)
[![Security](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/security.yml/badge.svg)](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/security.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)](pyproject.toml)
[![Network](https://img.shields.io/badge/network-none-success)](docs/adr/0002-local-only-no-backend.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

</div>

`fpr` is a command-line tool (with an optional desktop app) that removes password
protection from files you can already open, and adds a password to files that have
none. It runs entirely on your machine — there is no server and no network code.

**Scope, honestly:**

- Works on PDF, OOXML (`.docx` / `.xlsx` / `.pptx` and related), ZIP (WinZip AES and
  legacy ZipCrypto), and — via an optional extra — 7-Zip. `protect` supports PDF and ZIP.
- **You must supply the correct password.** It never cracks, guesses or brute-forces —
  no dictionary, no retry loop, no recovery mode.
- The original file is opened read-only and preserved (unless you pass `--in-place`).
- Every output is re-opened from disk and checked against the input before it is kept;
  a file that cannot be proved good is scrubbed and never written under the target name.
- It will not strip permission flags from a document you cannot authenticate against, and
  it never touches DRM, IRM or certificate-based encryption.

---

## Install

Requires Python 3.10–3.13.

```bash
pipx install git+https://github.com/Jayanth-reflex/file-password-remover
```

Optional extras — 7-Zip support (`sevenzip`, pulls in the LGPL `py7zr`) and the
desktop GUI (`gui`, adds the `fpr-gui` command):

```bash
pipx install "file-password-remover[sevenzip,gui] @ git+https://github.com/Jayanth-reflex/file-password-remover"
```

Standalone bundles, a signed Docker image, and mobile builds are described in
[docs/ops/install.md](docs/ops/install.md).

---

## Quick start

Run `fpr` with no arguments for a menu that names every command and what it does to
your files:

<p align="center">
<img src="docs/assets/cli-menu.svg" alt="The fpr menu: inspect reads only, remove unlocks, protect locks, plus formats and version" width="600">
</p>

**Inspect** — no password, changes nothing:

```console
$ fpr inspect quarterly-report.pdf
quarterly-report.pdf
  format       PDF (pdf)
  protection   user-password
  algorithm    AES-256 (PDF 2.0, R6)
  removable    removable
```

**Remove** — the password is prompted for, never echoed, never stored. Success is
reported only after the output is re-read and verified:

```console
$ fpr remove quarterly-report.pdf
Password:
✓ VERIFIED  quarterly-report-unprotected.pdf
   removed     user-password
   algorithm   AES-256 (PDF 2.0, R6)

   ENCRYPTED  PAGES  DIGEST            SCOPE
   false      12     7c411878be0a3889  all 12 page(s)

   original    quarterly-report.pdf (unchanged)
```

**Protect** — add a password (yours, or one it generates) to a PDF or ZIP:

```console
$ fpr protect notes.pdf --generate
✓ PROTECTED  notes-protected.pdf
   PASSWORD    w5zd-mzy4-d6g8-s4g5-npvk
   Save this now. It is shown once, and this tool cannot recover it.
```

> [!WARNING]
> A generated password is the only copy that will ever exist — this tool refuses to
> crack files back open. Use `--password-out FILE` to write it to a file (owner-only
> `0600` on macOS/Linux) instead of the terminal.

**Scripting** — feed the password without it touching `argv`, the environment or the
disk. There is deliberately no `--password VALUE` flag ([ADR-0007](docs/adr/0007-no-password-on-argv.md)):

```bash
printf '%s' "$PASSWORD" | fpr --json remove report.pdf --password-stdin
```

`--json` works on `inspect`, `remove`, `protect` and `formats`, and includes the
verification block — useful for agents and CI. Batch a folder with
`remove <dir> --recursive --pattern '*.docx' --output-dir ./clean`. Full flag and
recipe reference: [docs/ops/cli.md](docs/ops/cli.md).

---

## Exit codes

Stable and part of the contract; anything other than `0` means nothing was written.

| Code | Name | Meaning |
| ---: | :--- | :--- |
| 0 | `OK` | Success, verified |
| 1 | `UNEXPECTED` | A bug — please report it |
| 2 | `USAGE` | Bad arguments |
| 3 | `WRONG_PASSWORD` | The format's verifier rejected the password |
| 4 | `UNSUPPORTED_FORMAT` | Not a format, or protection, this tool handles |
| 5 | `CORRUPT_FILE` | Structurally damaged or truncated |
| 6 | `NOT_PROTECTED` | Nothing to remove |
| 7 | `OUTPUT_EXISTS` | Refusing to clobber; pass `--overwrite` |
| 8 | `IO_ERROR` | Permissions, disk, unreadable path |
| 9 | `VERIFICATION_FAILED` | Output failed its read-back check and was discarded |
| 10 | `POLICY_REFUSED` | Would be a bypass, not a removal |
| 11 | `DEPENDENCY_MISSING` | An optional extra is needed (e.g. `[sevenzip]`) |
| 12 | `PARTIAL_FAILURE` | A batch where at least one item failed |
| 130 | `INTERRUPTED` | Ctrl-C |

---

## Supported formats

| Format | Protection handled | Remove | Protect | Engine |
| :--- | :--- | :---: | :---: | :--- |
| **PDF** `.pdf` | Standard security handler R2–R6 (RC4-40/128, AES-128/256) | ✅ | ✅ | pikepdf / qpdf |
| **Office** `.docx` `.xlsx` `.pptx` *(+ related)* | ECMA-376 agile (2010+) and standard (2007) | ✅ | — | msoffcrypto-tool |
| **ZIP** `.zip` | WinZip AES-128/192/256, legacy ZipCrypto | ✅ | ✅ | pyzipper |
| **7-Zip** `.7z` | AES-256, incl. encrypted headers | ✅ | — | py7zr ([optional extra](docs/adr/0006-optional-lgpl-sevenzip-extra.md)) |
| **Legacy Office** `.doc` `.xls` `.ppt` | RC4 / CryptoAPI — **experimental**, needs `--experimental` | ✅ | — | msoffcrypto-tool |

Run `fpr formats` for the live list, including what is deliberately unsupported and why.
Full matrix: [docs/product/format-matrix.md](docs/product/format-matrix.md).

---

## Platforms

| Platform | CLI | Desktop GUI | Status |
| :--- | :---: | :---: | :--- |
| macOS 13+ (Apple silicon · Intel) | ✅ | ✅ | Built and tested in CI |
| Linux (glibc 2.28+) | ✅ | ✅ | Built and tested in CI |
| Windows 10+ | ✅ | ✅ | Built and tested in CI |
| Docker / air-gapped | ✅ | — | Signed image on GHCR |
| Android 8+ | — | ✅ app | Built in CI; sideloaded, not in a store |
| iOS 17+ | — | ✅ app | Built and verified on the Simulator; sideloaded |

The mobile apps are built from this repository and tested against the same encrypted
files as the CLI, but are sideloaded rather than store-published (no paid developer
accounts). Format coverage differs slightly — 7-Zip is Android-only, legacy Office is
detection-only. Details: [ADR-0011](docs/adr/0011-ship-mobile-apps-verified-not-published.md)
and [mobile/README.md](mobile/README.md).

---

## Security model

- **Nothing is uploaded.** There is no network code; a test parses every module and
  fails the build if a networking import appears, then blocks `socket.connect` and runs
  a real removal. ([ADR-0002](docs/adr/0002-local-only-no-backend.md))
- **The password** lives in a wipeable buffer that refuses to be logged, pickled or
  formatted, and is zeroed when the operation ends.
- **Temporary files** are `0600` inside a `0700` directory, scrubbed on every exit path
  (with the honest caveat that overwriting is not reliable erasure on SSDs / CoW
  filesystems — [L-16](docs/reports/known-limitations.md)).
- **Verify before publish.** Output is re-opened with the format's normal reader and
  checked against the input's invariants; on any mismatch it is discarded with exit `9`.
  This proves output matches input, not that the input was complete.
  ([ADR-0004](docs/adr/0004-verify-before-publish.md))
- **No bypass.** Permission flags are removed only with the owner password and an
  explicit `--remove-restrictions`. ([ADR-0008](docs/adr/0008-owner-restriction-policy.md))

More: [threat model](docs/security/threat-model.md) ·
[security design](docs/security/security-design.md) ·
[abuse cases](docs/security/abuse-cases.md) ·
[privacy](PRIVACY.md) · [report a vulnerability](SECURITY.md).

---

## Documentation

| | |
| :--- | :--- |
| 📖 **Using it** | [CLI reference](docs/ops/cli.md) · [Install](docs/ops/install.md) · [Uninstall](docs/ops/uninstall.md) |
| 🧭 **Scope** | [Requirements](docs/product/requirements.md) · [Format matrix](docs/product/format-matrix.md) |
| 🏛 **Design** | [Architecture decisions (ADRs)](docs/adr/) · [Project graph](docs/graph/project-graph.md) |
| 🔐 **Security** | [Threat model](docs/security/threat-model.md) · [Abuse cases](docs/security/abuse-cases.md) |
| ✅ **Quality** | [Verification report](docs/reports/verification-report.md) · [Known limitations](docs/reports/known-limitations.md) |
| 🤖 **For AI agents** | [agents.md](https://file-password-remover.vercel.app/agents.md) · [llms.txt](https://file-password-remover.vercel.app/llms.txt) |
| 🛠 **Contributing** | [CONTRIBUTING.md](CONTRIBUTING.md) · [Build](docs/ops/build.md) · [Release](docs/ops/release.md) |

---

## License

Apache-2.0 — see [LICENSE](LICENSE). The default distribution and the signed binaries
depend only on permissively licensed libraries. The optional 7-Zip support pulls in
`py7zr` (**LGPL-2.1-or-later**), which is why it is a separate extra and is not bundled
into released binaries; see [ADR-0006](docs/adr/0006-optional-lgpl-sevenzip-extra.md)
and [NOTICE](NOTICE).
