# Open-source landscape

Survey carried out before any code was written, to decide what to build on and
what to refuse. Every claim about a version, a release date or a licence in
this document was read from a primary source during the survey and the raw
responses are kept in [`evidence/`](evidence/): `pypi-metadata.json` (PyPI's
own JSON API) and `osv-scan-deps.json` (the OSV vulnerability database).
Anything that could not be verified is marked as unverified rather than
asserted.

Survey date: **2026-09-19**.

## Selection criteria

1. **Licence** must allow redistribution in an Apache-2.0 project, including
   in a signed binary. Weak copyleft (MPL) is acceptable; LGPL is acceptable
   only as an optional, separately installed extra; anything that restricts
   *use* is rejected outright.
2. **Maintenance**: a release within roughly the last 18 months, or a format so
   frozen that inactivity is not a risk.
3. **Security history**: no unresolved advisory at the version we pin.
4. **Scope**: decrypts with a supplied password. Anything whose purpose is
   *recovering* a password is out of scope by policy, not by preference.

## PDF

| Project | Licence | Latest (uploaded) | Verdict |
| --- | --- | --- | --- |
| [**pikepdf**](https://github.com/pikepdf/pikepdf) | MPL-2.0 | 10.13.0.post1 (2026-09-05) | **Adopted** |
| [qpdf](https://github.com/qpdf/qpdf) | Apache-2.0 | 12.3.2 (bundled inside pikepdf wheels) | Adopted transitively |
| [pypdf](https://github.com/py-pdf/pypdf) | BSD-3-Clause | actively maintained | Rejected for this job |
| [PyMuPDF](https://github.com/pymupdf/PyMuPDF) | AGPL-3.0 or commercial | active | **Rejected** |
| [pdfcpu](https://github.com/pdfcpu/pdfcpu) | Apache-2.0 | active | Rejected (Go; would force a second toolchain) |

*pikepdf* wraps qpdf, which is the reference-quality C++ implementation of the
PDF standard security handler and covers R2–R6 (RC4-40 through AES-256). It
exposes `user_password_matched` / `owner_password_matched`, which is the
single API that makes this project's no-bypass policy enforceable rather than
aspirational: without it there is no way to tell "the user supplied the owner
password" from "the document simply has no user password". The licence chain
was read out of the installed wheel: pikepdf is MPL-2.0, and its bundled
components are declared in `pikepdf-*.dist-info/licenses/third-party-licenses/`
— qpdf Apache-2.0, libjpeg-turbo IJG+BSD-3-Clause+Zlib, and (Windows only)
statically linked OpenSSL and zlib.

*pypdf* is a fine library but its AES-256 support has historically lagged and
it has no equivalent of the owner/user distinction; using it would mean
implementing the policy check ourselves against the raw `/Encrypt` dictionary.

*PyMuPDF* is AGPL-3.0 unless a commercial licence is bought. That is a
deliberate business model and a perfectly legitimate one; it is simply
incompatible with shipping an Apache-2.0 tool that people can redistribute.

## Office documents

| Project | Licence | Latest (uploaded) | Verdict |
| --- | --- | --- | --- |
| [**msoffcrypto-tool**](https://github.com/nolze/msoffcrypto-tool) | MIT | 6.0.0 (2026-01-12) | **Adopted (decryption only)** |
| [olefile](https://github.com/decalage2/olefile) | BSD-2-Clause | 0.47 (2023-12-01) | Adopted transitively (read-only) |
| LibreOffice headless | MPL-2.0 | — | Rejected (a ~1 GB dependency to decrypt a file) |

*msoffcrypto-tool* implements ECMA-376 agile and standard encryption plus the
legacy Office 97–2003 schemes, and is the de-facto standard for this in Python.
Its age (the 5.4.2 → 6.0.0 gap spans August 2024 to January 2026) is acceptable
because the formats it implements are frozen specifications, not moving targets.

**We use it to decrypt only.** Its *encryption* side in 6.0.0 produces a
malformed OLE container — see [02-format-notes.md](02-format-notes.md) for the
reproduction — so the project writes its own encryptor for test fixtures. That
turned out to be a benefit rather than a workaround: the fixtures are now
produced by an implementation independent of the one under test.

*olefile* cannot write compound files at all
([decalage2/olefile#6](https://github.com/decalage2/olefile/issues/6)), which is
why `fpr/testing/cfb.py` exists.

## Archives

| Project | Licence | Latest (uploaded) | Verdict |
| --- | --- | --- | --- |
| [**pyzipper**](https://github.com/danifus/pyzipper) | MIT | 0.4.0 (2026-05-14) | **Adopted** |
| Python `zipfile` (stdlib) | PSF | — | Adopted for *writing* the output |
| [**py7zr**](https://github.com/miurahr/py7zr) | LGPL-2.1-or-later | 1.1.3 (2026-06-19) | **Adopted as an optional extra** |
| [rarfile](https://github.com/markokr/rarfile) + unrar | rarfile ISC, **unrar non-free** | — | **Rejected** |
| [libarchive](https://github.com/libarchive/libarchive) | BSD-2-Clause | active | Rejected (no ZipCrypto/WinZip-AES *write* parity; large C dependency) |

*pyzipper* is a fork of the standard library's `zipfile` with WinZip AES
support; it reads both AES-128/192/256 and legacy ZipCrypto. The four-year gap
between 0.3.6 (2022) and 0.4.0 (2026) was noted and accepted: the code is a
thin layer over a frozen format plus pycryptodome, the 2026 release shows it is
not abandoned, and it carries no open advisories at the pinned version.

*py7zr* is the only maintained pure-Python 7z implementation. It is
LGPL-2.1-or-later, so it is an opt-in extra and is excluded from the released
binaries; see [ADR-0006](../adr/0006-optional-lgpl-sevenzip-extra.md).

*RAR is rejected on licence grounds.* The only complete decoder is RARLAB's
unrar, whose licence forbids using the source to re-create the RAR compression
algorithm and requires that restriction to be passed on; the Fedora Project
classifies it as non-free and GPL-incompatible
([Fedora: Licensing:Unrar](https://fedoraproject.org/wiki/Licensing:Unrar)).
`fpr` therefore detects RAR files, names them, and explains the exclusion
instead of silently reporting "unsupported".

## Deliberately not evaluated

Password *recovery* tools — John the Ripper's `*2john` family, hashcat,
`pdfcrack`, and the commercial "instant unlocker" products — were not evaluated
as dependencies or as inspiration. They solve the opposite problem. Their
existence is relevant only as the abuse case this project is designed not to
become; see [abuse-cases.md](../security/abuse-cases.md).

DRM removal tooling (ebook DeDRM plugins, Widevine/FairPlay work) is out of
scope permanently, for the reasons in
[format-matrix.md](../product/format-matrix.md#permanently-unsupported).

## Cross-platform application frameworks

| Option | Verdict |
| --- | --- |
| **Tkinter (stdlib)** | **Adopted.** Ships with CPython everywhere, adds no dependency to audit, keeps the bundle small |
| PySide6 / Qt | Rejected: LGPL-3 with bundling obligations, ~150 MB of payload, and a much larger attack surface for a four-control window |
| Electron / Tauri | Rejected: a second language runtime and a browser engine for a local file operation |
| Kivy / BeeWare | Considered for the mobile story; see [mobile/README.md](../../mobile/README.md) |

See [ADR-0005](../adr/0005-desktop-toolkit.md) for the full trade-off,
including what Tkinter costs us (no drag-and-drop, plain visuals).

## Packaging and distribution

| Option | Verdict |
| --- | --- |
| **PyInstaller** | Adopted for desktop bundles: one directory/onefile per OS, mature, no runtime dependency on a system Python |
| Briefcase (BeeWare) | Viable and closer to native installers; more moving parts than this release needs |
| Nuitka | Rejected: compilation adds risk and build time for no user-visible benefit here |
| Native `.pkg` / MSI / `.deb` | Documented in [release.md](../ops/release.md); they need signing identities this project does not hold |

## Summary of what was adopted

| Component | Licence | Role | Bundled in binaries? |
| --- | --- | --- | --- |
| pikepdf (+ qpdf) | MPL-2.0 (+ Apache-2.0) | PDF decryption | Yes |
| msoffcrypto-tool | MIT | Office decryption | Yes |
| pyzipper | MIT | ZIP decryption | Yes |
| py7zr | LGPL-2.1-or-later | 7z decryption | **No — optional extra** |
| Tkinter | PSF | Desktop UI | Yes (part of CPython) |
