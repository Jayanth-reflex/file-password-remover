# ADR-0009: Generate protected fixtures ourselves, independently of the readers under test

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Test

## Context

Testing a decryptor needs encrypted files. There are three ways to get them,
and two of them are bad:

1. **Commit binary samples.** Opaque blobs in the repository, impossible to
   review in a diff, flagged by scanners, and sometimes someone else's
   document.
2. **Round-trip through the library under test.** Encrypt and decrypt with the
   same code. Any shared misunderstanding of the format cancels out and the
   test passes while the product is wrong.
3. **Generate them from an independent implementation.**

Option 2 was the plan until `msoffcrypto-tool` 6.0.0's encryptor turned out to
write a malformed OLE container (reproduction:
`scripts/repro_msoffcrypto_encrypt.py`, write-up in
[format notes §2](../research/02-format-notes.md)).

## Decision

Everything protected is generated at test time, from code in this repository:

| Module | What it writes | Validated against |
| --- | --- | --- |
| `fpr/testing/cfb.py` | OLE/CFB v3 containers (FAT, mini-FAT, directory trees) | `olefile` |
| `fpr/testing/ooxml_agile.py` | ECMA-376 agile encryption, from [MS-OFFCRYPTO] | `msoffcrypto-tool` |
| `fpr/testing/zipcrypto.py` | Traditional PKWARE (ZipCrypto) archives, from APPNOTE.TXT | `pyzipper` and stdlib `zipfile` |
| `fpr/testing/fixtures.py` | PDFs (pikepdf), AES ZIPs (pyzipper), 7z (py7zr), legacy Office FIBs | the adapters |

Two of these are genuine cross-implementation checks: our encryptor writes,
someone else's decryptor reads. That is a stronger statement than any round
trip.

## Where it is *not* independent, and we say so

PDF fixtures are written by pikepdf and read by pikepdf; likewise 7z with
py7zr. Writing a PDF encryptor or a 7z container writer to break that symmetry
would be a large amount of code to test someone else's library. The residual
risk is recorded as **R-12** in the threat model, and mitigated by the fact
that the PDF fixtures are additionally checked against *content* invariants
(page counts and decoded content-stream digests) rather than just "it opened".

## Consequences

*Good*: no binaries in git; every fixture is reviewable as source; fixture
generation doubles as executable documentation of three file formats; the
Office tests are cross-implementation.

*Bad*: about 700 lines of test-only format code to maintain, including a CFB
writer. It is covered at 96–99 % and is not imported by anything the user runs.

## Reversal cost

Low but pointless — the generators are now the only way to get an encrypted
OOXML fixture from open tooling.
