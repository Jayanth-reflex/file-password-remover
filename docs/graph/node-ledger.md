# Node ledger

What actually happened at each graph node, including every failure and what it
cost. The failures are the useful part of this document: a build record that
contains none is a build record that was written afterwards.

Format: **what broke → how it was found → the smallest safe correction → what
was re-run.**

---

## Node 1 — Audit the host

Clean. Findings that shaped later nodes: Python 3.13.5, Xcode present, **no
Android SDK, no Gradle, no signing identities, no LibreOffice**. The last one
removed "generate Office fixtures with a headless office suite" as an option;
the middle ones decided [ADR-0010](../adr/0010-no-mobile-app-this-release.md).

## Node 2 — Research

No failures. Three decisions came out of it: unrar rejected on licence,
py7zr demoted to an optional extra, and pyzipper's four-year release gap
accepted with a documented fallback plan (R-11).

## Nodes 3–7 — Scope, boundaries, stack, structure, core

No failures. `mypy --strict` and `ruff` were green from the first run because
the contracts were written before the implementations.

## Node 8 — Adapters

Seven failures, all found by tests.

### 8.1 `pikepdf.Page.contents_coalesce()` returns `None`

**Found**: `TypeError: sequence item 0: expected a bytes-like object, NoneType
found` in the first PDF round-trip test. In pikepdf 10.x the method mutates the
page and returns nothing; older versions returned the bytes.

**Fix**: a `page_content_bytes()` helper that reads `/Contents` directly,
handling both a single stream and an array, and decoding through `read_bytes()`
so a re-compression by qpdf does not look like a content change.

**Re-ran**: `tests/integration/test_pdf.py`, then the full suite.

### 8.2 `encryption.user_password` does not mean what it looks like

**Found**: `test_owner_password_also_decrypts` failed with a policy refusal.
The attribute reports the password that was *supplied*, not the document's own,
so a document with a real user password opened with the owner password looked
like a document with no user password at all.

**Fix**: classify a restriction-only run from two reliable facts — does the
document open with an empty password, and did the supplied password match as
the *user* password. Written up in
[format notes §3](../research/02-format-notes.md).

**Re-ran**: the PDF suite, the security suite, and the policy unit tests —
because this is the code the whole no-bypass policy rests on.

### 8.3 A PDF with an empty *owner* password is not protected

**Found**: while fixing 8.2. `Encryption(user="pw", owner="")` opens with the
empty owner password, so every PDF tool can read and re-save it.

**Fix**: detection reports it explicitly instead of implying strong protection.
Two regression tests added, one for the report and one proving the real open
password still decrypts it normally.

### 8.4 R2/R3 cannot carry AES or encrypted metadata

**Found**: `ValueError: Cannot encrypt with AES when R < 4` on the parametrised
revision test.

**Fix**: fixture generation sets `aes=` and `metadata=` from the revision.
R5 was added to the parametrisation at the same time, after checking that qpdf
*can* write it (it can, with a deprecation warning that the fixture now
suppresses deliberately).

### 8.5 `Permissions()` denies `modify_assembly` by default

**Found**: an "encrypted, no restrictions" fixture was classified as
`BOTH`.

**Fix**: fixtures spell out all eight flags. A separate test was added for a
genuinely restricted-and-encrypted document, so the `BOTH` path is still
covered.

### 8.6 py7zr 1.x removed the in-memory read API

**Found**: `AttributeError: 'SevenZipFile' object has no attribute 'readall'`.

**Fix**: the adapter now extracts into a `0700` temp directory on the
destination's filesystem and repacks, with entry-name validation against
absolute paths and `..` added at the same time. A wrong password surfaces as a
raw `_lzma.LZMAError`, which is translated rather than reported as damage.

### 8.7 ZipCrypto's one-byte check produces three different errors

**Found**: `test_wrong_zipcrypto_password_is_rejected` failed intermittently
with `zlib.error: Error -3 while decompressing data: invalid block type` —
a wrong password that passed the one-byte verifier.

**Fix**: `zlib.error` on an *encrypted* entry is mapped to
`IncorrectPasswordError` with a message naming both possibilities in order of
likelihood; on an unencrypted entry it stays a corruption error. Re-ran five
times to confirm stability.

## Node 9 — CLI

No failures.

## Node 10 — Desktop

Four failures, all in the tests rather than the product — which is the point of
having them.

### 10.1 The GUI test suite hung

**Found**: the first test passed, the run then hung indefinitely. Creating and
destroying several `Tk()` roots in one process hangs on macOS.

**Fix**: a session-scoped root whose children are rebuilt per test.

### 10.2 A leaked `after` timer

**Found**: while fixing 10.1 — the queue poller rescheduled itself forever, so
a shared root accumulated one poller per test.

**Fix**: `App.stop()` cancels the job; `main()` calls it in a `finally`.

### 10.3 The keyboard-reachability test was vacuous

**Found**: it failed on a withdrawn window. ttk's `takefocus` handler reports
that a widget declines focus while it is not viewable, so *every* control
looked unreachable — the test would have passed just as happily against a
window with no controls at all.

**Fix**: deiconify, walk the ring, withdraw again.

### 10.4 "Show in folder" looked enabled while disabled

**Found**: in the release screenshot. ttk's aqua theme renders a disabled
button almost identically to an enabled one.

**Fix**: hide the button until there is a result. Absence is unambiguous where
"greyed out" is not. Test added.

## Node 12 — Secure handling

### 12.1 A deprecated call, caught by the test configuration

**Found**: `DeprecationWarning: 'locale.getdefaultlocale' is deprecated and
slated for removal in Python 3.15`, raised as an error by the project's
`filterwarnings` setting.

**Fix**: `locale.getlocale()`, which is not deprecated and does not mutate
global state the way `setlocale()` would.

## Node 13 — Fixtures

### 13.1 msoffcrypto-tool 6.0.0 writes a malformed OLE container

**Found**: a round trip through the library failed with
`InvalidKeyError: The file could not be decrypted with this password` on a
*correct* password. Investigation showed `olefile` and `msoffcrypto` reading
different bytes for the same stream name — the directory entries point at the
wrong sectors.

**Fix**: wrote the container and the encryption instead — `testing/cfb.py` (CFB
v3 writer, validated against olefile) and `testing/ooxml_agile.py` (ECMA-376
agile, from the specification). Reproduction preserved as
`scripts/repro_msoffcrypto_encrypt.py` and documented in
[format notes §2](../research/02-format-notes.md).

**Outcome**: better than the original plan. Office fixtures are now written by
an implementation independent of the one under test.
[ADR-0009](../adr/0009-own-fixture-generators.md).

### 13.2 No fixture exists for legacy Office decryption

**Found**: by trying. No open tool produces an RC4-encrypted BIFF8 or Word 97
document.

**Fix**: split the claim. Detection *is* testable — a hand-built File
Information Block with the `fEncrypted` bit set is enough — so detection is
covered, and decryption is gated behind `--experimental` and labelled
everywhere it surfaces.

## Node 14 — Tests

Coverage of `password_input.py` (51 %) and `cli/output.py` (75 %) was too low
to claim the interfaces were tested. 40 tests added; overall coverage
85 % → 89 %.

## Node 15 — CI

No failures. The `no-extras` job exists because the py7zr decision is only real
if something checks it.

## Node 16 — Build

### 16.1 The frozen binary could not start

**Found**: by the build script's own smoke test —
`ImportError: attempted relative import with no known parent package`.
PyInstaller runs its entry script as `__main__`, which breaks every relative
import if you point it at a module inside the package.

**Fix**: `packaging/pyinstaller/entry_cli.py` and `entry_gui.py`.

**Note**: PyInstaller reported *"Build complete!"* immediately before this.
The build step is only meaningful because the script then runs the artifact,
decrypts a real fixture with it, and verifies the output independently.

### 16.2 `checksums.sh` failed on the bundle directory

**Found**: `sha256sum: file-password-remover: Is a directory`.

**Fix**: skip directories; checksum the distributions and archives.

## Node 17 — Review

### 17.1 bandit flagged the file-manager launch

**Found**: B603/B607 — `explorer` and `xdg-open` were invoked by bare name,
resolved through `PATH`.

**Fix**: resolve absolute paths per platform (`/usr/bin/open`,
`%SYSTEMROOT%\explorer.exe`, `xdg-open` from a fixed list of system
directories) and return `None` when none is found. Real hardening, not a
suppression: `PATH` is writable by anything running as the user.

### 17.2 ruff formats Python inside Markdown

**Found**: `ruff format --check` failed on
`docs/security/security-design.md`. A code block in the documentation was
badly aligned.

**Fix**: reformatted. Worth keeping: it means the examples in the docs are held
to the same standard as the code.

## Nodes 18–20 — Fix loop, documentation, sign-off

The fix loop above *is* node 18: every correction re-ran its own node and the
suites downstream of it. Nodes 19 and 20 produced
[verification-report.md](../reports/verification-report.md),
[production-readiness.md](../reports/production-readiness.md) and
[independent-review.md](../reports/independent-review.md).
