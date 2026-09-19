# ADR-0004: Never publish an output that has not been re-read and verified

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture / Test

## Context

The failure mode that matters most in this product is not crashing — it is
**cheerfully reporting success over a damaged file**. A user who trusts the
message deletes the original, and the loss is discovered weeks later. Every
library in the stack has at least one path where an operation "succeeds" and
produces something subtly wrong:

- qpdf *recovers* a truncated PDF and hands back one page where there were
  three (see [format notes §5](../research/02-format-notes.md));
- a wrong ZipCrypto password passes its one-byte check about 1 time in 256 and
  produces plausible-looking bytes;
- AE-2 ZIP entries store a CRC of zero, so the format's own integrity field is
  not available.

## Decision

The engine publishes a result only after this sequence:

1. `adapter.remove()` writes into a private temp file **and returns evidence**:
   invariants captured from the decrypted input (PDF page count and per-page
   decoded content-stream digests; ZIP/OOXML per-entry SHA-256, sizes, names
   and part lists).
2. `adapter.verify()` re-opens **that file from disk** with the format's normal
   reader, asserts it is no longer protected, and recomputes the same
   invariants.
3. Any mismatch raises `VerificationError`; the temp file is scrubbed and
   nothing appears at the destination. Exit code 9.
4. Only then does `os.replace` publish the file, followed by an `fsync` of the
   directory.

The success message repeats the evidence back to the user
(`verified encrypted=false, pages=3, content_digest=…`) so that "it worked" is
a claim with a receipt.

## What this does and does not prove

**Proves**: the written file is openable by the format's own reader, carries no
encryption, and has the same content as what we read out of the source.

**Does not prove**: that the *source* was complete. A truncated input yields a
faithful decryption of a truncated input. No tool can do better without the
missing bytes; the honest response is to say so, which
[known-limitations](../reports/known-limitations.md) does.

## Alternatives considered

**Trust the library's return value.** Cheapest, and wrong for the reasons above.

**Byte-for-byte comparison of input and output.** Impossible: decryption
legitimately changes the bytes.

**Full re-decryption of the source for comparison.** Doubles the work and still
compares against the same reader; the digest-of-decoded-content approach gets
the same assurance for one extra pass.

## Consequences

*Good*: no silent corruption; failures are loud and leave nothing behind.

*Bad*: every removal reads its own output once more. On a 200 MiB archive that
is a measurable second. Above `VERIFY_PAGE_CAP` (400) pages the PDF adapter
samples rather than hashing every page, and **says so** in the report
(`content_scope: 100 of 2000 page(s), every 20`) rather than implying a full
check.

## Reversal cost

None — it would be a removal. It is the property the product is built on.
