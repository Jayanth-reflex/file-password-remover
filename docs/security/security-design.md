# Security and privacy design

How the controls in the [threat model](threat-model.md) are actually built.
Cross-references are to real symbols so a reviewer can go straight to them.

## 1. The password

`fpr/secret.py`. A `Secret` owns a `bytearray` — the only mutable byte buffer
CPython offers — and zeroes it on `close()`, with a `weakref.finalize` backstop
for the case where someone forgets.

```python
with Secret.from_fd(read_fd) as pw:  # never touches argv, env or disk
    result = remove(path, pw)
# pw._buf is now b"" and pw.expose() raises
```

Leak-proofing is deliberate rather than incidental:

| Escape route | Blocked by |
| --- | --- |
| `repr()`, `str()`, f-strings, `%`, `format()` | all return `<Secret 9 bytes>` / `<Secret wiped>` |
| `pickle`, `copy`, `deepcopy` | `__reduce__` / `__copy__` / `__deepcopy__` raise |
| `bytes(secret)` | raises; callers must use `expose_bytes()` explicitly |
| `==` between secrets | identity only — no content comparison, no timing oracle |
| logging | no call site passes it; `RedactionFilter` scrubs credential-shaped text anyway |
| tracebacks | the value is a local inside a context manager, not an attribute of any object a frame dump would render |

**What it cannot do**, said plainly: `Secret.expose()` must hand the underlying
library a `str`, and that `str` is immutable and unwipeable. The window is one
function call wide and we drop our reference immediately, but a memory dump
taken during a decryption can contain the password. `mlock` is not used: it
needs privileges we do not want, fails silently in containers, and would imply
a guarantee we cannot keep.

## 2. Getting the password in

`fpr/cli/password_input.py`, and [ADR-0007](../adr/0007-no-password-on-argv.md).
Ranked by exposure: `--password-fd` (none) → `--password-stdin` → interactive
`getpass` → `--password-file` (warns if group/world readable) →
`--password-env` (warns loudly). `--password VALUE` is parsed only so it can be
refused with a useful message.

The GUI takes the password out of its Tk `StringVar` the moment a run starts
and clears the field, because a `StringVar` lives as long as the widget.

## 3. Files on disk

`fpr/securefs.py`.

- **Private temp**: `secure_tempdir()` creates `0700`; `atomic_write()` creates
  the temp file `0600` **in the destination's own directory**, so the final
  `os.replace` is a same-filesystem rename and plaintext never lands on a
  second volume.
- **Atomic publish**: write → `fsync` the file → `os.replace` → `fsync` the
  directory. A crash at any point leaves either the old file or the new one,
  never a truncated file with a confident name.
- **Never clobber**: an existing destination is refused unless `--overwrite`;
  the check is repeated immediately before the rename.
- **Restrictive output**: the output keeps the temp file's `0600`. It does not
  inherit a source file that happened to be world-readable.
- **Scrubbing**: every failure path overwrites the temp file with zeros,
  `fsync`s, and unlinks. The docstring states the limit — on SSDs with wear
  levelling and on copy-on-write filesystems this raises the cost of casual
  recovery and nothing more.

## 4. Deciding whether to act

`fpr/policy.py` holds rules R1–R5 in one place, and `policy.check()` runs on a
**password-free** detection so a refusal happens before the user is asked for a
secret. Adapters enforce the same rules again at the point of decryption, so a
future caller that skips the engine still cannot bypass them.

## 5. Proving the result

[ADR-0004](../adr/0004-verify-before-publish.md). `verify()` re-opens the
written file from disk and compares invariants captured from the decrypted
input:

| Format | Invariants |
| --- | --- |
| PDF | not encrypted; page count; SHA-256 over every page's **decoded** content stream (sampled above 400 pages, and the sampling is reported); doc-info keys and XMP presence reported |
| OOXML | not an OLE container; valid ZIP; part count; digest of names; digest of per-part CRC + size; `[Content_Types].xml` present |
| ZIP | no entry has the encryption bit; entry count; SHA-256 of every entry's decrypted bytes; total size |
| 7z | `needs_password()` false; entry count; SHA-256 per extracted file; total size |
| Legacy Office | not encrypted; the expected Office stream still present |

A mismatch raises `VerificationError`, the output is scrubbed, exit code 9.

## 6. Logging

`fpr/logging_setup.py`. Default level is WARNING; `-v`/`-vv` raise it. Every
handler carries `RedactionFilter`, which rewrites anything matching
`password|passwd|passphrase|secret|pwd` followed by a value. Third-party
loggers (`pikepdf`, `msoffcrypto`, `PIL`) are capped at INFO because their
debug output can echo file content.

No log file is written by default. Nothing is sent anywhere.

## 7. Input validation

- `assert_readable_file()` rejects directories, FIFOs, devices and empty files
  with specific messages instead of letting a parser produce something cryptic.
- Identification is by magic bytes and structure, never by extension; a
  mismatch is reported.
- ZIP expansion is capped (16 GiB total, 2000:1 per entry) while streaming.
- 7z entry names are rejected if absolute or containing `..`, before extraction.
- Password material is capped at 4096 bytes — anything longer is a mistake,
  usually a file that is not a password file.

## 8. Supply chain

- Every dependency is pinned with an upper bound and justified in
  [the licence analysis](../research/01-dependency-license-analysis.md).
- `pip-audit` and an OSV query run in CI on every push and weekly on a
  schedule.
- `bandit` runs over `src/` with zero findings at the configured level.
- Hash-pinned installs are documented in [release.md](../ops/release.md) for
  anyone who wants them; we do not yet verify wheel signatures (R-16).

## 9. Privacy

See [PRIVACY.md](../../PRIVACY.md). In one line: the tool reads the files you
point it at and writes the output you ask for; it collects nothing, stores
nothing and sends nothing.
