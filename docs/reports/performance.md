# Performance

Measured on the development host; reproduce with `make test-slow`.

| | |
| --- | --- |
| Host | Apple silicon (arm64), macOS 27 |
| Python | 3.13.5 |
| Build | `pikepdf` 10.13.0.post1 / libqpdf 12.3.2, `pyzipper` 0.4.0, `msoffcrypto-tool` 6.0.0 |

## What was measured

`tests/perf/test_large_files.py`, run with `pytest -m slow`:

| Case | Shape | Budget | Observed |
| --- | --- | --- | --- |
| Large PDF | 600 pages, AES-256 (R6) | < 60 s | ≈ 0.1 s |
| Large ZIP | 200 MiB, 200 entries, AES-256, stored (incompressible) | < 180 s | ≈ 2.2 s |
| Many small files | 100 single-page encrypted PDFs in one batch | < 60 s | ≈ 2.0 s |

The budgets are deliberately loose. They exist to catch a **regression in
complexity** — a change that makes verification quadratic, or that starts
buffering an archive in memory — not to advertise a throughput number that
depends entirely on the host.

## Memory

The ZIP test asserts that processing a 200 MiB archive grows peak RSS by less
than 120 MiB, which it does because the adapter streams each entry in 1 MiB
chunks through a hash and into the output, and never holds an entry whole.

The fixture for that test is written straight to disk rather than through a
`BytesIO`: `ru_maxrss` is a high-water mark, so a 200 MiB buffer in the test
itself would poison the baseline and make the assertion meaningless. That
detail is noted here because it is the kind of thing that silently turns a
memory test into decoration.

**Office decryption is the exception.** `msoffcrypto` decrypts the package into
a single in-memory buffer, so peak memory is roughly the document size. That is
an upstream constraint, recorded as
[L-09](known-limitations.md) rather than worked around with a fake stream.

## Where the time goes

| Format | Dominant cost |
| --- | --- |
| PDF | qpdf's parse and rewrite; verification adds one more pass over the decoded content streams |
| ZIP | AES-CTR + HMAC per entry (pycryptodome, C), then deflate; verification re-reads and re-hashes every entry |
| OOXML | The key derivation, which is 100 000 iterations of SHA-512 by design. Roughly 0.1 s and constant regardless of document size |
| 7z | LZMA decompression, plus a full extract-and-repack through a temp directory because py7zr 1.x has no in-memory read API |

Verification roughly doubles the read work. That is the cost of
[ADR-0004](../adr/0004-verify-before-publish.md), and it is the right trade:
the alternative is a success message that might be false.

## Deliberate limits

| Limit | Value | Why |
| --- | --- | --- |
| `MAX_TOTAL_UNCOMPRESSED` | 16 GiB | A decompression bomb is a denial of service against the person running the tool |
| `MAX_COMPRESSION_RATIO` | 2000:1 per entry | Legitimate data reaches 1000:1 (sparse logs); 2000:1 essentially does not |
| `VERIFY_PAGE_CAP` | 400 pages | Above this, PDF verification samples deterministically and **says so** in the report |
| `MAX_PASSWORD_BYTES` | 4096 | Anything longer is a mistake, usually a file that is not a password file |

## Not measured

- Windows and Linux throughput. CI runs the suite there for correctness, but
  the timing budgets were not tuned on those runners.
- Cold-start time of the frozen bundle, which is dominated by PyInstaller's
  unpacking and is noticeably slower than the pip-installed CLI.
- Spinning disks. Every measurement here is on NVMe.
