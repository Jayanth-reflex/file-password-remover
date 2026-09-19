# Supported-format matrix

Four categories, kept separate on purpose:

- **Encryption removable after the password validates** — the content is
  genuinely encrypted, and supplying the password is decryption.
- **Restrictions removable with the owner password** — the content is *not*
  encrypted; flags ask software to forbid printing or copying. Removing them is
  only legitimate with the owner password, and only when explicitly requested.
- **Cannot be removed reliably** — detected, reported, refused.
- **Permanently unsupported** — technical, legal or licensing reasons, stated.

Run `fpr formats` for the same information from the tool itself.

---

## Encryption removable after the password validates

| Format | Extensions | Scheme | Adapter | Fixture | Round-trip test |
| --- | --- | --- | --- | --- | --- |
| PDF | `.pdf` | Standard security handler **R2** (RC4-40) | `adapters/pdf.py` | `PdfSpec(revision=2)` | `test_pdf.py::test_every_supported_revision[2]` |
| PDF | `.pdf` | **R3** (RC4-128) | " | `PdfSpec(revision=3)` | `…[3]` |
| PDF | `.pdf` | **R4** (RC4-128 or AES-128) | " | `PdfSpec(revision=4)` | `…[4]` |
| PDF | `.pdf` | **R6** (AES-256, PDF 2.0) | " | `PdfSpec(revision=6)` | `…[6]` |
| PDF | `.pdf` | **R5** (AES-256, Adobe ext. 3, deprecated) | " | `PdfSpec(revision=5)` | `…[5]` |
| Word / Excel / PowerPoint | `.docx` `.docm` `.dotx` `.dotm` `.xlsx` `.xlsm` `.xltx` `.xltm` `.xlsb` `.pptx` `.pptm` `.potx` `.potm` `.ppsx` `.ppsm` | ECMA-376 **agile** (AES-CBC + SHA-512, Office 2010+) | `adapters/ooxml.py` | `fpr/testing/ooxml_agile.py` | `test_ooxml.py::test_decrypts_every_office_type` |
| Word / Excel / PowerPoint | as above | ECMA-376 **standard** (AES-128 + SHA-1, Office 2007) | " | — | Implemented; detected by type. No fixture generator written for the 2007 scheme — see limitations |
| ZIP | `.zip` | **WinZip AES** 128 / 192 / 256 (AE-1, AE-2) | `adapters/zipfiles.py` | `make_zip_aes(bits=…)` | `test_zip.py::test_every_aes_strength` |
| ZIP | `.zip` | **ZipCrypto** (traditional PKWARE) | " | `fpr/testing/zipcrypto.py` | `test_zip.py::test_contents_round_trip[zip_zipcrypto]` |
| 7-Zip *(optional extra)* | `.7z` | AES-256, incl. encrypted headers | `adapters/sevenzip.py` | `make_sevenzip()` | `test_sevenzip.py` |

### Experimental

| Format | Extensions | Scheme | Why experimental |
| --- | --- | --- | --- |
| Legacy Office 97–2003 | `.doc` `.dot` `.xls` `.xlt` `.ppt` `.pot` `.pps` | RC4 / RC4 CryptoAPI | **Detection is tested; decryption is not.** No open tool can *produce* an encrypted BIFF8 or Word 97 document, and no sample can be safely redistributed, so there is no fixture for the decryption path. Requires `--experimental`, and says so in every message. |

---

## Restrictions removable with the owner password

| Format | What it is | Behaviour |
| --- | --- | --- |
| PDF permission flags | Printing / copying / editing denied, **no** open password | Refused by default. With `--remove-restrictions` **and** a password that qpdf confirms is the owner password, the flags are cleared. Any other password is rejected by the format itself — there is no way in. |
| PDF with an empty owner password | `user="pw", owner=""` | Reported as *"any tool can open and re-save this; the restrictions are not enforceable"*. Decrypts normally when the open password is supplied. |

---

## Cannot be removed reliably — reported and refused

| Format | What it is | Why we refuse |
| --- | --- | --- |
| Word `<w:documentProtection>` | "Restrict editing", read-only enforcement | The document is **not encrypted**. The password exists only as a hash; "removing" it means deleting an XML element without checking anything. That is a bypass. Use Word's own *Stop Protection*. |
| Excel `<workbookProtection>` / sheet protection | Structure and sheet locks | Same reasoning. The legacy variant uses a 16-bit hash with enormous collision rates, so even "verifying" it would be theatre. |
| PowerPoint `<p:modifyVerifier>` | Modification password | Same reasoning. |
| PDF certificate security | `/Filter /Adobe.PubSec` | Encrypted to a certificate. Needs the matching private key from a key store, not a password. |
| Office IRM / extensible encryption | Rights-managed documents | The key lives on a rights server. Nothing to remove offline. |

---

## Permanently unsupported

| Format | Reason |
| --- | --- |
| **RAR** (`.rar`) | The only complete decoder is RARLAB's unrar, whose licence forbids using the sources to re-create the RAR algorithm and requires that restriction to propagate. Fedora classifies it as non-free and GPL-incompatible. No compatible clean-room decoder exists. |
| **DRM-protected ebooks** (`.acsm`, Kindle, Apple Books) | Circumventing DRM is a different act from removing your own password, and is unlawful in many jurisdictions. |
| **Encrypted disk images and volumes** (`.dmg`, VeraCrypt, BitLocker, LUKS) | These are volumes, not documents. Use the operating system's own tooling, which handles mounting, integrity and recovery keys properly. |
| **Password managers / key stores** (`.kdbx`, `.p12`, `.jks`) | A decrypted password database is a worse artifact than the encrypted one. Use the manager's own export. |
| **Formats with no password protection** (PNG, JPEG, gzip, bzip2, xz, plain tar) | There is nothing to remove. The tool names the format and says so rather than reporting a generic failure. |
| **"Locked" PDFs with no encryption at all** | Some tools flatten a PDF and call it locked. Nothing is encrypted; there is nothing to do. |

---

## How a format graduates

1. A fixture generator that produces a **valid** protected file, ideally
   independent of the library that will read it.
2. A round-trip test proving content is preserved byte for byte where the
   format allows it.
3. A wrong-password test proving no output is written.
4. A corrupt-file test proving the error is not misreported as a bad password.
5. Post-write verification implemented in the adapter's `verify()`.
6. A row in this table and in `fpr formats`.

Steps 1–5 are why legacy Office decryption is still experimental. Until a
fixture exists, it does not get to look finished.
