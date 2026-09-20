<div align="center">

# File Password Remover

**Unlock the files you own — on your own machine, with proof the result is intact.**

[![CI](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/ci.yml/badge.svg)](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/ci.yml)
[![Security](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/security.yml/badge.svg)](https://github.com/Jayanth-reflex/file-password-remover/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/Jayanth-reflex/file-password-remover?sort=semver)](https://github.com/Jayanth-reflex/file-password-remover/releases)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-276%20passing-brightgreen)](docs/reports/verification-report.md)
[![No network](https://img.shields.io/badge/network-none-success)](docs/adr/0002-local-only-no-backend.md)

```bash
pip install file-password-remover
fpr remove quarterly-report.pdf
```

</div>

---

You have a PDF, a spreadsheet or a ZIP that you have the password for, and you
are tired of typing it. The usual answer is to upload the file — **and the
password** — to a website you have never heard of.

This does the same job locally. No server, no account, no telemetry. The
package contains no network code at all, and there is a test that fails the
build if anyone adds any.

<div align="center">
<img src="docs/assets/desktop-verified.png" alt="The desktop app after unlocking a 12-page PDF, showing the verification line: encrypted=false, pages=12, content digest and scope" width="700">
<br><em>The desktop app. That <code>Verified:</code> line is a read-back of the file that was just written — not a canned message.</em>
</div>

---

## Why not just use an online unlocker?

|  | Online "unlock PDF" sites | `fpr` |
| --- | --- | --- |
| Where your file goes | Their server | Nowhere. It never leaves the disk |
| Where your password goes | Their server | A wipeable buffer in local memory |
| What happens to the file afterwards | Their retention policy | Nothing; there is no "afterwards" |
| Proof the output is intact | None | Page counts and content digests, compared before and after |
| Works offline / air-gapped | No | Yes |
| Cost per file | Freemium, then paid | None |
| Will it strip protection you cannot authenticate? | Usually yes | **No — and that is the point** |

That last row is the one that matters. Most "unlockers" work by opening a PDF
with an *empty* password and re-saving it without the permission flags. That is
a bypass, not a decryption. This tool refuses to do it unless you supply the
owner password — see [ADR-0008](docs/adr/0008-owner-restriction-policy.md).

## What it does and does not do

**Will** decrypt a file when you supply a password the file's own verifier
accepts, then write a new, unencrypted copy.

**Will not** recover, guess or brute-force a password. Will not strip
permission flags off a document you cannot authenticate against. Will not touch
DRM, Information Rights Management, or certificate-based encryption. These are
enforced in code, not just promised in a README — run `fpr formats` to see the
boundary, or read [the abuse cases](docs/security/abuse-cases.md), each of
which has a test proving the refusal.

| Class of protection | Example | What happens |
| :--- | :--- | :--- |
| 🔓 **Content encryption** | PDF open password · `.docx` "Encrypt with Password" · AES `.zip` | Removed once the password validates |
| 🔒 **Permission restrictions** | PDF with printing disabled and *no* open password | Removed **only** with the owner password and `--remove-restrictions` |
| 🚫 **Editing restrictions** | `<w:documentProtection>` in Word, sheet protection in Excel | Reported and refused — the content is not encrypted, so removal would be a bypass |
| ⛔ **Rights management / DRM** | IRM, `Adobe.PubSec`, ebook DRM | Reported, never touched |

## Supported formats

| Format | Protection handled | Engine |
| :--- | :--- | :--- |
| **PDF** `.pdf` | Standard security handler R2–R6 — RC4-40, RC4-128, AES-128, AES-256 | pikepdf / qpdf |
| **Word · Excel · PowerPoint** `.docx` `.xlsx` `.pptx` (+ 12 more) | ECMA-376 agile (Office 2010+) and standard (2007) | msoffcrypto-tool |
| **ZIP** `.zip` | WinZip AES-128/192/256, legacy ZipCrypto | pyzipper |
| **7-Zip** `.7z` | AES-256 including encrypted headers | py7zr — [optional extra](docs/adr/0006-optional-lgpl-sevenzip-extra.md) |
| **Legacy Office** `.doc` `.xls` `.ppt` | RC4 / CryptoAPI | msoffcrypto-tool — **experimental**, needs `--experimental` |

Full matrix, including everything deliberately unsupported and why:
[docs/product/format-matrix.md](docs/product/format-matrix.md).

## Install

<table>
<tr><td width="50%">

**pip** — the CLI, the desktop app and the Python API

```bash
pip install file-password-remover
```

With 7-Zip support:

```bash
pip install "file-password-remover[sevenzip]"
```

</td><td width="50%">

**pipx** — isolated, just the commands

```bash
pipx install file-password-remover
```

**Docker** — nothing installed, parsers sandboxed

```bash
docker run --rm -v "$PWD:/data" \
  --user "$(id -u):$(id -g)" \
  ghcr.io/jayanth-reflex/file-password-remover \
  inspect /data/report.pdf
```

</td></tr>
</table>

Standalone bundles for macOS, Linux and Windows — no Python needed — are on the
[releases page](https://github.com/Jayanth-reflex/file-password-remover/releases).
They are **unsigned**; verify the checksum and see
[install.md](docs/ops/install.md) for what your OS will say about that.

## Use it

```console
$ fpr inspect quarterly-report.pdf
quarterly-report.pdf
  format       PDF (pdf)
  protection   user-password
  algorithm    AES-256 (PDF 2.0, R6)
  removable    removable
  note         Encrypted. Supply the open (user) password or the owner password.

$ fpr remove quarterly-report.pdf
Password:
✓ /home/you/quarterly-report-unprotected.pdf
  removed      user-password
  algorithm    AES-256 (PDF 2.0, R6)
  size         2.3 MiB -> 2.2 MiB in 0.41s
  verified     encrypted=false, pages=12, content_digest=7c411878be0a3889, content_scope=all 12 page(s)
  original     /home/you/quarterly-report.pdf (unchanged)
```

A whole folder, one password, machine-readable:

```bash
fpr remove ~/archive --recursive --pattern '*.docx' --output-dir ./clean --json
```

Scripted, without the password ever touching `argv`, the environment or the disk:

```bash
printf '%s' "$PASSWORD" | fpr remove book.pdf --password-stdin
```

> **There is no `--password VALUE` flag.** Command lines are readable by every
> process on the machine and land in your shell history, so the tool refuses
> the idea and points you at the safe routes.
> ([ADR-0007](docs/adr/0007-no-password-on-argv.md))

Desktop app: `fpr-gui`. Full CLI reference, exit codes and recipes:
[docs/ops/cli.md](docs/ops/cli.md).

## How you know it actually worked

Most tools print "Done" when the write call returns. That is not the same thing
as the file being good — qpdf will silently *recover* a truncated PDF and hand
back 3 pages where there were 12.

So `fpr` never reports success on a write. It reports success on a **read-back**:

```
  1. decrypt into a private 0600 temp file, on the destination's own filesystem
  2. re-open that file from disk with the format's normal reader
  3. assert it is no longer protected
  4. recompute content invariants — page counts, per-page content-stream
     digests, per-entry SHA-256 — and compare with the input
  5. only then: fsync, os.replace, fsync the directory
```

If step 3 or 4 fails, the output is scrubbed and the run exits `9`. A file that
cannot be proved good never reaches the name you asked for.
([ADR-0004](docs/adr/0004-verify-before-publish.md))

## Security and privacy

- **Nothing is uploaded.** Not configurable — there is no network code.
  `tests/security/test_no_network.py` parses every module and fails the build
  if a networking import appears, then blocks `socket.connect` and runs a real
  removal to catch anything indirect.
- **The password** lives in a wipeable buffer that refuses to be logged,
  pickled, copied or formatted, and is zeroed when the operation ends.
- **Temporary files** are `0600` inside a `0700` directory on the output's own
  filesystem, overwritten and deleted on every path including failures — with
  the honest caveat that overwriting does not reliably erase on SSDs or
  copy-on-write filesystems.
- **The original** is opened read-only and never modified unless you pass
  `--in-place`, which still verifies before replacing.

[Threat model](docs/security/threat-model.md) ·
[Security design](docs/security/security-design.md) ·
[Abuse cases](docs/security/abuse-cases.md) ·
[Privacy](PRIVACY.md) ·
[Report a vulnerability](SECURITY.md)

## Platform support

| Platform | CLI | Desktop | Status |
| :--- | :---: | :---: | :--- |
| macOS 13+ (Apple silicon · Intel) | ✅ | ✅ | Built and tested |
| Linux (glibc 2.28+) | ✅ | ✅ | Built and tested in CI |
| Windows 10+ | ✅ | ✅ | Built and tested in CI |
| Docker / air-gapped | ✅ | — | Image published to GHCR |
| iOS · Android | — | — | **Not shipped.** [Why, and what a port would take](mobile/README.md) |

## Project quality

| | |
| :--- | :--- |
| Tests | **276** — unit, integration, security, performance |
| Coverage | 88 % |
| Type checking | `mypy --strict`, zero issues |
| Static analysis | `bandit`, zero findings |
| Dependencies | 9 pinned, **zero known advisories**, all permissively licensed |
| Fixtures | Generated from the specs — the Office and ZIP tests decrypt files written by an *independent* implementation |

Reproduce the lot with one command:

```bash
bash scripts/run_verification.sh     # 16 gates, logs to artifacts/verification/
```

Evidence, including what was **not** verified:
[verification report](docs/reports/verification-report.md) ·
[independent review](docs/reports/independent-review.md) ·
[known limitations](docs/reports/known-limitations.md) (25 entries, with IDs)

## Documentation

| | |
| :--- | :--- |
| 📖 **Using it** | [CLI reference](docs/ops/cli.md) · [Install](docs/ops/install.md) · [Uninstall](docs/ops/uninstall.md) |
| 🧭 **Scope** | [Requirements](docs/product/requirements.md) · [Format matrix](docs/product/format-matrix.md) |
| 🏛 **Design** | [10 ADRs](docs/adr/) · [Project graph](docs/graph/project-graph.md) · [Build ledger](docs/graph/node-ledger.md) |
| 🔐 **Security** | [Threat model](docs/security/threat-model.md) · [Abuse cases](docs/security/abuse-cases.md) |
| 🔬 **Research** | [Library survey](docs/research/00-open-source-landscape.md) · [Licences](docs/research/01-dependency-license-analysis.md) · [Format notes](docs/research/02-format-notes.md) |
| ✅ **Quality** | [Verification](docs/reports/verification-report.md) · [Readiness](docs/reports/production-readiness.md) · [Performance](docs/reports/performance.md) |
| ♿ **Inclusion** | [Accessibility](docs/product/accessibility.md) · [Localization](docs/product/localization.md) |
| 🛠 **Contributing** | [CONTRIBUTING.md](CONTRIBUTING.md) · [Build](docs/ops/build.md) · [Release](docs/ops/release.md) |

Full map: [docs/README.md](docs/README.md).

## Licence

[Apache-2.0](LICENSE). Third-party components and their licences are in
[NOTICE](NOTICE), analysed in
[docs/research/01-dependency-license-analysis.md](docs/research/01-dependency-license-analysis.md).

<div align="center">
<sub>Built because uploading a confidential document to a stranger's server to remove a password you already know is a bad trade.</sub>
</div>
