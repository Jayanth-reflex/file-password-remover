# Format notes and upstream findings

Things learned while building the adapters that are not obvious from the
specifications, and that changed a design decision. Each one has a
reproduction.

---

## 1. An encrypted `.docx` is not a ZIP

A plain Office Open XML file starts `50 4B 03 04` (`PK\x03\x04`). An *encrypted*
one starts `D0 CF 11 E0 A1 B1 1A E1` — it is an OLE/CFB compound file whose
`EncryptedPackage` stream holds the real ZIP, with an `EncryptionInfo` stream
describing the key derivation ([MS-OFFCRYPTO] 2.3.4).

Consequence for this project: detection keys off content, and the OOXML adapter
has to claim *both* magic numbers and then decide. It also means a user who
renames `secret.docx` to `secret.zip` still gets correct handling — and is told
about the mismatch rather than quietly humoured.

```bash
python -c "
import sys; sys.path.insert(0,'src')
from fpr.testing import fixtures as F
print(F.make_docx()[:4], F.make_encrypted_ooxml(F.make_docx())[:4])"
# b'PK\x03\x04' b'\xd0\xcf\x11\xe0'
```

---

## 2. msoffcrypto-tool 6.0.0 writes a malformed OLE container

**Severity for us: none at runtime** (we never encrypt); **decisive for
testing**.

`msoffcrypto.format.ooxml.OOXMLFile.encrypt()` produces a file whose directory
entries point at the wrong sectors, so reading `EncryptedPackage` back returns
the bytes of `EncryptionInfo`. The round trip therefore fails with
`InvalidKeyError: The file could not be decrypted with this password` even when
the password is correct.

Reproduction — `scripts/repro_msoffcrypto_encrypt.py` in this repository:

```
$ python scripts/repro_msoffcrypto_encrypt.py
plaintext package      : 922 bytes
EncryptedPackage (olefile read)   : 936 bytes, header says 274878169092 bytes of plaintext
password verification            : PASSED (the key schedule is fine)
EncryptedPackage (msoffcrypto read): starts 04 00 04 00 40 00 00 00
    ^ that is EncryptionInfo's version header, not the package
round trip                       : InvalidKeyError: The file could not be decrypted with this password

verdict: the two readers disagree about which stream is which -> malformed container
our own writer round-trips cleanly:
    fpr.testing.ooxml_agile -> msoffcrypto: identical = True
```

The container writer itself
(`msoffcrypto/method/container/ecma376_encrypted.py`) carries the comment
*"Probably very brittle"* and notes that olefile cannot write compound files
([decalage2/olefile#6](https://github.com/decalage2/olefile/issues/6)).

**What we did about it.** Rather than depend on a broken encryptor or vendor a
patched copy, the project writes its own:

- `src/fpr/testing/cfb.py` — a CFB v3 writer (512-byte sectors, mini-FAT,
  balanced directory trees), validated against olefile;
- `src/fpr/testing/ooxml_agile.py` — ECMA-376 agile encryption implemented
  from [MS-OFFCRYPTO] 2.3.4.10 onward.

That turned a workaround into an improvement: Office fixtures are now produced
by an implementation **independent of the one under test**, so
`tests/integration/test_ooxml.py` is a genuine cross-implementation check
rather than a round trip through one code path.

---

## 3. `pikepdf.encryption.user_password` does not mean what it looks like

It reports the password *that was supplied*, not the document's own user
password. Opening a document whose user password is `"userpw"` with the **owner**
password reports `user_password == b""`, which reads exactly like "this document
has no user password".

The project's whole restriction policy hangs on telling those two cases apart,
so the check was rewritten to use facts that are actually reliable:

```python
opens_with_empty_password = _opens_without_password(source)  # a separate open
user_matched = pdf.user_password_matched  # for the supplied password
restriction_only = opens_with_empty_password and not user_matched
```

`tests/integration/test_pdf.py::test_empty_owner_password_still_decrypts_with_the_real_open_password`
is the regression test for the original mistake.

---

## 4. A PDF with an empty *owner* password is not protected

`Encryption(user="pw", owner="")` is a common real-world shape. qpdf opens such
a file with the empty owner password, which means every PDF tool can read and
re-save it regardless of the user password. Detection cannot see whether a
separate open password also exists, so the tool says what it can prove:

> This PDF's owner password is empty, so any tool can open and re-save it and
> its restrictions are not enforceable.

```bash
python -c "
import sys, io, pikepdf; sys.path.insert(0,'src')
from fpr.testing import fixtures as F
p = pikepdf.open(io.BytesIO(F.make_pdf(F.PdfSpec(user='pw', owner=''))))
print('opened with empty password; owner_matched =', p.owner_password_matched)"
```

---

## 5. qpdf silently recovers truncated PDFs — with fewer pages

A PDF truncated to 50 % of its length still opens, and reports **1 page**
instead of 3. Only at around 30 % does qpdf give up with
`root of pages tree has no /Pages`.

This is why the engine does not treat "the file opened" as success. It captures
the page count and a digest of every page's decoded content stream from the
input and compares them against the written output. Note the honest limit of
that check: it proves the *output matches the input*, not that the input was
complete. A user handed a truncated file gets a faithful decryption of a
truncated file, and no tool can do better without the missing bytes.

---

## 6. ZipCrypto's password check is one byte wide

Traditional PKWARE encryption (APPNOTE.TXT 6.1) verifies a password against a
single byte, so roughly **1 in 256** wrong passwords is accepted and the error
only surfaces later. In practice it surfaces three different ways:

| What happens | Where it appears |
| --- | --- |
| Verifier rejects it (the usual case) | `RuntimeError: Bad password for file ...` |
| Verifier passes, deflate stream is garbage | `zlib.error: Error -3 while decompressing data` |
| Verifier passes, data decompresses, CRC fails | `BadZipFile: Bad CRC-32` |

All three are mapped to `IncorrectPasswordError` (exit 3) with a message that
names both possibilities in order of likelihood. Getting this wrong in either
direction is a real usability failure: "the archive is damaged" sends someone
hunting for a corruption that does not exist, and a bare "wrong password"
overstates what the format can actually tell us.

WinZip AES is different and better: a 2-byte verifier (1 in 65 536) plus an
HMAC-SHA1 authentication code over every entry, which pyzipper checks.

---

## 7. AE-2 archives store a CRC of zero

WinZip AES version AE-2 sets each entry's CRC-32 field to zero by
specification, because the authentication code supersedes it. Any verification
built on comparing stored CRCs would therefore be comparing `0` with `0` and
proving nothing. The ZIP adapter hashes the decrypted bytes of every entry with
SHA-256 instead, on both sides of the write.

---

## 8. py7zr 1.x removed the in-memory read API

`SevenZipFile.readall()` and `.read()` are gone in py7zr 1.1.x; only
`extract`/`extractall` remain. The adapter therefore expands into a `0700`
temporary directory on the destination's own filesystem and repacks from there,
scrubbing the tree afterwards. A wrong password surfaces as a raw
`_lzma.LZMAError: Corrupt input data` from the decompressor, which the adapter
translates rather than reporting as file damage.

---

## 9. `os.fsync` needs a writable descriptor on Windows

Not a format note, but the same shape of problem: an API that is more
permissive on one platform than another.

`atomic_write` reopened the finished temp file read-only purely to `fsync` it
before the rename. That is fine on POSIX. On Windows `os.fsync` maps to
`_commit()`, which rejects a read-only descriptor:

```
OSError: [Errno 9] Bad file descriptor
```

Every Windows run failed on it, and it was invisible on macOS and Linux. The
fix is one flag — open `O_RDWR` — and the regression test asserts the flag
rather than the behaviour, so it fails on any platform if someone changes it
back.

It was found by the release pipeline's Windows bundle job decrypting a real
file with the frozen binary, which is the argument for smoke-testing an
artifact rather than trusting that a build which printed "complete" produced
something that works.

## 10. R2/R3 PDFs cannot carry AES or encrypted metadata

qpdf refuses `Encryption(R=2, aes=True)` with *"Cannot encrypt with AES when
R < 4"* and likewise for `metadata=True`. Only relevant to fixture generation,
but it is the kind of detail that makes a parametrised test mysteriously fail
on two of its four cases.
