# ADR-0012: Guard py7zr's decompressor against making no progress

**Status**: Accepted · **Date**: 2026-09-27 · **Owner**: Engineering

## Context

A CI job hung for five minutes in
`tests/integration/test_sevenzip.py::test_wrong_password_is_rejected`, inside
py7zr's extraction loop. The cause is in py7zr 1.1.3, the latest release:

```python
while out_remaining > 0:
    tmp = decompressor.decompress(fp, min(out_remaining, max_block_size))
    ...
```

Nothing in the loop checks for progress. A wrong AES key usually decrypts to
bytes the LZMA decoder rejects at once. Occasionally -- about one key in 400 --
it decrypts to bytes the decoder accepts until the packed input is used up.
From then on each call reads nothing and returns nothing, and the loop never
ends. For the user, `fpr remove archive.7z` with a mistyped password hangs
indefinitely. Nothing is written, but nothing tells them why.

It looked platform-specific because the test fixtures drew a random IV each
run. Pinning the IV (`fpr.testing.fixtures.SEVENZIP_STALLING_IV`) makes it
reproducible on every Python and platform tried.

The same search found a second rare outcome: the wrong key decodes to an early
LZMA end-of-stream marker, py7zr raises `EOFError`, and the engine reported it
as an I/O error (exit 8) instead of a wrong password (exit 3).

## Decision

Wrap `py7zr.compressor.SevenZipDecompressor.decompress` once, when the 7-Zip
adapter is imported. The wrapper counts calls that return no data **and** leave
the archive's file position unchanged, and after three in a row raises an
internal `_NoProgressError`, which the adapter reports as a wrong password
(with the usual "or the archive is damaged" remediation). `EOFError` from
extraction is reported the same way.

Progress is judged only by the return value and `fp.tell()`, both public; the
wrapper does not read py7zr's private counters. In any extraction that can
complete, every call either produces output or reads input, so behaviour
changes only in the state that could otherwise only hang.

## Alternatives considered

**Run the extraction in a child process and kill it on a deadline.** This
would also contain hangs nobody has found yet, which is a real advantage. It
was rejected for this one known loop because:

- the deadline has to scale with archive size, and any fixed value is either
  too short for a large archive or too long to help;
- the password would have to cross a process boundary. `Secret` refuses
  pickling by design, so it would go over a pipe -- workable, but a second copy
  of the secret in a second process for the lifetime of the extraction;
- process spawning is slow on Windows and awkward inside the frozen desktop
  bundles.

If a second hang of unknown cause turns up in py7zr, this should be revisited,
and isolation will probably be the right answer.

**Wait for an upstream fix.** The loop should be fixed in py7zr, and should be
reported there. But the hang affects users now, and an upstream release would
also need a version floor on the optional extra. When one exists, the guard can
be removed and the floor raised.

**Pre-check the password.** 7-Zip's AES coder has no password verifier; only
decompressing tells a right key from a wrong one.

## Consequences

- A wrong 7-Zip password now fails in well under a second in every case found:
  400 randomly keyed archives each exited 3 under Python 3.10, where the hang
  was first seen.
- This is a patch to a third-party class, installed at import and affecting any
  py7zr use in the same process. That is acceptable because py7zr is imported
  only by this adapter and the change is limited to a state that cannot finish.
- **Tripwire.** If a py7zr release moves or renames the decompressor, the guard
  skips itself rather than breaking the import, and
  `test_the_no_progress_guard_is_installed` fails, naming this ADR. The
  regression test runs the stalling archive in a child process with a
  60-second deadline, so a guard that silently stops working fails the suite
  instead of hanging it.
