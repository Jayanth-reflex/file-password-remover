# Known limitations

Everything this release does not do, or does imperfectly. Ordered by how likely
it is to matter.

## Platforms

| # | Limitation | Consequence | Workaround |
| --- | --- | --- | --- |
| L-01 | **No iOS or Android application.** | The tool is unavailable on phones and tablets as a native app. | The CLI runs under a-Shell/iSH (iOS) or Termux (Android), which is a workaround rather than support. See [mobile/README.md](../../mobile/README.md) and [ADR-0010](../adr/0010-no-mobile-app-this-release.md). |
| L-02 | **Bundles are unsigned.** | macOS Gatekeeper and Windows SmartScreen warn. | Verify the SHA-256, or install via `pip`, which is verified through PyPI. Signing steps: [release.md](../ops/release.md). |
| L-03 | **Only macOS arm64 was built and run on the development host.** Linux and Windows bundles are produced by CI. | Platform-specific bundle bugs on Linux/Windows would be caught by CI's smoke test, not by a human. | The CI job runs the same `scripts/build_desktop.sh`, which decrypts a real fixture and verifies the output. |

## Formats

| # | Limitation | Consequence | Workaround |
| --- | --- | --- | --- |
| L-04 | **Legacy Office (.doc/.xls/.ppt) decryption is experimental.** Detection is tested; decryption has no fixture, because no open tool can produce an encrypted BIFF8 or Word 97 document. | The path is off by default and unproven. | `--experimental`, then check the output opens before deleting the original. |
| L-05 | **ECMA-376 *standard* encryption (Office 2007) has no fixture.** The code path exists and is selected by detection, but only the *agile* scheme is exercised by a test. | An Office 2007-era encrypted file is handled by untested code. | Reported honestly here; a standard-scheme generator is the obvious next fixture. |
| L-06 | **No RAR support, permanently.** | `.rar` archives cannot be processed. | Use WinRAR or `unar`. Reason: [format matrix](../product/format-matrix.md#permanently-unsupported). |
| L-07 | **Office editing restrictions are refused, not removed.** | A "Restrict editing" Word document stays restricted. | Use the application's own *Stop Protection*. This is a deliberate policy, [ADR-0008](../adr/0008-owner-restriction-policy.md). |
| L-08 | **No DRM, IRM or certificate-based decryption.** | Rights-managed files are out of reach. | None. Permanently out of scope. |

## Behaviour

| # | Limitation | Consequence | Workaround |
| --- | --- | --- | --- |
| L-09 | **Office decryption buffers the whole package in memory** (an msoffcrypto constraint). | Peak memory ≈ document size. A 2 GiB PowerPoint needs 2 GiB free. | Use the CLI on a machine with headroom. PDF and ZIP stream and do not have this problem. |
| L-10 | **Verification proves output == input, not that the input was complete.** qpdf silently recovers a truncated PDF with fewer pages; the tool faithfully decrypts what is there. | A truncated source produces a truncated output, reported as success. | Check the page count in the report against what you expect. |
| L-11 | **PDFs over 400 pages are verified by sampling**, not page by page. | A corruption confined to an unsampled page would not be caught. | The report states the sampling explicitly (`content_scope: 100 of 2000 page(s), every 20`). |
| L-12 | **ZipCrypto wrong-password detection is ambiguous.** The format's check is one byte wide. | A wrong password is *usually* detected; about 1 in 256 slip through to a CRC or decompression failure, which the tool reports as "probably the wrong password, possibly a damaged archive". | Inherent to the format. |
| L-13 | **Batch mode uses one password for every file.** | Files with different passwords fail. | Run the batch once per password, or script over `fpr --json inspect`. |
| L-14 | **No progress bar for a single large file.** | A multi-gigabyte archive looks idle. | Batch mode prints one line per file; a single file's progress needs adapter-level callbacks that do not exist yet. |
| L-15 | **No drag-and-drop in the desktop window.** | An expected interaction is missing. | Use *Choose file…*. Reason: Tk needs the external `tkdnd` package, [ADR-0005](../adr/0005-desktop-toolkit.md). |

## Security

| # | Limitation | Consequence | Workaround |
| --- | --- | --- | --- |
| L-16 | **Temp-file scrubbing cannot guarantee erasure.** Overwriting does not reliably touch the physical blocks on SSDs, APFS, Btrfs or ZFS. | Forensic recovery of decrypted temp data may be possible. | Full-disk encryption. Risk R-05. |
| L-17 | **The password exists briefly as an unwipeable Python `str`.** Every decryption API takes one. | A memory dump taken during decryption may contain it. | Inherent to the runtime. Risk R-07. |
| L-18 | **Parsers are not sandboxed.** | A malicious file exploiting qpdf, lxml or pycryptodome would run with the user's privileges. | Process untrusted files in a container or VM. Risk R-08. |
| L-19 | **No wheel signature verification.** | A compromised PyPI account could serve a malicious build. | `pip install --require-hashes` with a lock file you generated. Risk R-16. |
| L-26 | **The `0600`/`0700` modes on temporary files are inert on Windows.** `os.chmod` there only toggles the read-only attribute. | The restrictive-mode guarantee in the threat model is POSIX-only wording. | None needed: `tempfile` creates the file with an ACL granting only the creating user, which is the equivalent protection. Risk R-05. |

## Accessibility and localisation

| # | Limitation | Consequence | Workaround |
| --- | --- | --- | --- |
| L-20 | **The desktop window has not been tested with a screen reader**, and Tk exposes no accessibility tree. | Quality with VoiceOver, Narrator and Orca is unknown. No WCAG conformance is claimed for the window. | Use the CLI, which is fully accessible. [accessibility.md](../product/accessibility.md). |
| L-21 | **English is the only catalogue**, and engine/adapter messages are not externalised at all. | Non-English users read English explanations. | [localization.md](../product/localization.md) documents how to add a language. |
| L-22 | **Right-to-left layout is untested.** | Arabic and Hebrew layout quality is unknown. | None yet. |

## Project

| # | Limitation | Consequence |
| --- | --- | --- |
| L-23 | **Builds are not bit-for-bit reproducible.** PyInstaller embeds timestamps and paths. | You cannot independently reproduce a published binary byte for byte. Checksums are published instead. |
| L-24 | **PDF and 7z fixtures share an implementation with the reader under test.** | A shared misunderstanding of those formats would not be caught. Mitigated for PDF by comparing content invariants rather than "it opened". Risk R-12, [ADR-0009](../adr/0009-own-fixture-generators.md). |
| L-25 | **Coverage of `legacy_office.py` is 26 %**, by construction — the decryption branch has no fixture. | Reported rather than hidden behind a coverage threshold. |
