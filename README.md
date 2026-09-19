# File Password Remover

Remove password protection from files **you already have the password for** —
locally, with the original left untouched, and with the result verified before
it is called a success.

```bash
fpr inspect quarterly-report.pdf     # what protection is on this? (no password needed)
fpr remove  quarterly-report.pdf     # prompts, writes quarterly-report-unprotected.pdf
```

There is no server, no upload, no account and no telemetry. The package
contains no network code at all.

---

## What it will and will not do

**It will** decrypt a file when you supply a password that the file's own
verifier accepts, and then write a new, unencrypted copy.

**It will not** recover, guess, brute-force or crack a password; it will not
strip permission flags off a document you cannot authenticate against; and it
will not touch DRM, Information Rights Management, or certificate-based
encryption. Those are different acts from removing your own password, and the
[policy rules](docs/security/threat-model.md) are enforced in code, not just in
the documentation. Run `fpr formats` to see the boundary.

| Class of protection | Example | What happens |
| --- | --- | --- |
| Content encryption | PDF with an open password; `.docx` "Encrypt with Password"; AES `.zip` | Removed once the password validates |
| Permission restrictions | PDF with printing/copying disabled and *no* open password | Removed **only** with the owner password and `--remove-restrictions` |
| Editing restrictions | `<w:documentProtection>` in Word, sheet protection in Excel | Reported, refused — the content is not encrypted and removal would be a bypass |
| Rights management / DRM | IRM, Adobe.PubSec, ebook DRM | Reported, never touched |

The complete matrix, including every format that is deliberately unsupported
and why, is in [docs/product/format-matrix.md](docs/product/format-matrix.md).

## Supported formats

| Format | Protection handled | Backed by |
| --- | --- | --- |
| **PDF** (`.pdf`) | Standard security handler R2–R6: RC4-40, RC4-128, AES-128, AES-256 | pikepdf / qpdf |
| **Office Open XML** (`.docx` `.xlsx` `.pptx` and variants) | ECMA-376 agile (Office 2010+) and standard (Office 2007) | msoffcrypto-tool |
| **ZIP** (`.zip`) | Legacy ZipCrypto and WinZip AES-128/192/256 | pyzipper |
| **7-Zip** (`.7z`) | AES-256, including encrypted headers | py7zr — *optional extra*, see below |
| **Legacy Office** (`.doc` `.xls` `.ppt`) | RC4 / CryptoAPI | msoffcrypto-tool — **experimental**, `--experimental` required |

## Install

```bash
pip install file-password-remover
```

7-Zip support is an opt-in extra because `py7zr` is LGPL-2.1-or-later and the
default distribution stays permissively licensed
([ADR-0006](docs/adr/0006-optional-lgpl-sevenzip-extra.md)):

```bash
pip install "file-password-remover[sevenzip]"
```

Desktop app and platform-specific packages: [docs/ops/install.md](docs/ops/install.md).
Removing it again: [docs/ops/uninstall.md](docs/ops/uninstall.md).

## Using it

```bash
# Inspect first — this never asks for a password and never writes anything.
fpr inspect ~/Documents/*.pdf

# Single file; the original is left exactly as it was.
fpr remove report.pdf -o ~/Desktop/report-clean.pdf

# A folder, same password for all of them, machine-readable output.
fpr remove ~/archive --recursive --pattern '*.docx' --output-dir ./clean --json

# Non-interactive, without the password ever touching argv or the environment.
printf '%s' "$PASSWORD" | fpr remove book.pdf --password-stdin
```

There is no `--password VALUE` option. Command lines are readable by every
process on the machine and are saved in shell history, so the tool refuses the
idea outright and points you at `--password-fd`, `--password-file`,
`--password-stdin`, or the interactive prompt.

Exit codes are stable (`0` success, `3` wrong password, `4` unsupported, `9`
verification failed, `10` refused by policy, …) and listed in
[docs/ops/cli.md](docs/ops/cli.md).

### Desktop app

```bash
fpr-gui
```

A small Tk window: drop or choose a file, see what protection it carries, type
the password, pick where the copy goes. Same engine, same rules, same
verification. Keyboard-navigable and screen-reader labelled — see
[docs/product/accessibility.md](docs/product/accessibility.md).

## Why you can believe the success message

A "done" message is printed only after the engine has:

1. decrypted into a private temporary file (`0600`, same filesystem as the
   destination, scrubbed on any failure);
2. **re-opened that file from disk** and confirmed it is no longer protected;
3. re-computed content invariants — PDF page count and per-page content-stream
   digests, ZIP/OOXML per-entry digests and part lists — and compared them with
   what was read out of the source;
4. moved it into place with an atomic `os.replace`.

If step 2 or 3 fails, the output is scrubbed and the run exits `9`. A file that
cannot be proved good never reaches the name you asked for.

## Security and privacy

- The password is held in a wipeable buffer, is never logged, never put on a
  command line, and is zeroed when the operation ends.
- Temporary files live in a `0700` directory on the destination's own
  filesystem and are overwritten before deletion — with the honest caveat that
  overwriting does not reliably erase data on SSDs or copy-on-write
  filesystems.
- Nothing is uploaded. There is no analytics, no crash reporting, no update
  check.

Full threat model and accepted risks: [docs/security/threat-model.md](docs/security/threat-model.md).
Reporting a vulnerability: [SECURITY.md](SECURITY.md).
Privacy statement: [PRIVACY.md](PRIVACY.md).

## Platform support

| Platform | Status |
| --- | --- |
| macOS 13+ (Apple silicon, Intel) | CLI and GUI; built and tested |
| Linux (glibc 2.28+) | CLI and GUI; built in CI |
| Windows 10+ | CLI and GUI; built in CI |
| iOS / Android | **Not shipped.** See [mobile/README.md](mobile/README.md) for what a mobile build would require and why this release does not claim one |

Verified build and test evidence for this release, including what was *not*
verified: [docs/reports/verification-report.md](docs/reports/verification-report.md).

## Documentation

| | |
| --- | --- |
| Product scope, requirements | [docs/product/requirements.md](docs/product/requirements.md) |
| Supported-format matrix | [docs/product/format-matrix.md](docs/product/format-matrix.md) |
| Architecture decisions | [docs/adr/](docs/adr/) |
| Threat model & abuse cases | [docs/security/threat-model.md](docs/security/threat-model.md) |
| Open-source research & licences | [docs/research/](docs/research/) |
| CLI reference | [docs/ops/cli.md](docs/ops/cli.md) |
| Build, package, sign, release | [docs/ops/release.md](docs/ops/release.md) |
| Accessibility | [docs/product/accessibility.md](docs/product/accessibility.md) |
| Localization | [docs/product/localization.md](docs/product/localization.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Known limitations | [docs/reports/known-limitations.md](docs/reports/known-limitations.md) |

## Licence

Apache-2.0. Third-party components and their licences are listed in
[NOTICE](NOTICE) and analysed in
[docs/research/01-dependency-license-analysis.md](docs/research/01-dependency-license-analysis.md).
