#!/usr/bin/env python3
"""Reproduce the malformed container written by msoffcrypto-tool 6.0.0.

Documented in docs/research/02-format-notes.md, finding 2. This is why the
project writes its own ECMA-376 encryptor for fixtures instead of round-tripping
through the library it tests.

    python scripts/repro_msoffcrypto_encrypt.py
"""

from __future__ import annotations

import io
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import msoffcrypto  # noqa: E402
import olefile  # noqa: E402
from msoffcrypto.format.ooxml import OOXMLFile  # noqa: E402

from fpr.testing import fixtures as F  # noqa: E402


def main() -> int:
    plain = F.make_docx()
    print(f"plaintext package      : {len(plain)} bytes")

    workdir = Path(tempfile.mkdtemp())
    source, encrypted = workdir / "plain.docx", workdir / "enc.docx"
    source.write_bytes(plain)
    with source.open("rb") as fi, encrypted.open("wb") as fo:
        OOXMLFile(fi).encrypt("s3cret", fo)

    with olefile.OleFileIO(str(encrypted)) as ole:
        via_olefile = ole.openstream("EncryptedPackage").read()
    declared = struct.unpack("<Q", via_olefile[:8])[0]
    print(
        f"EncryptedPackage (olefile read)   : {len(via_olefile)} bytes, "
        f"header says {declared} bytes of plaintext"
    )

    with encrypted.open("rb") as fh:
        office = msoffcrypto.OfficeFile(fh)
        office.load_key(password="s3cret", verify_password=True)
        print("password verification            : PASSED (the key schedule is fine)")
        via_msoffcrypto = office.file.openstream("EncryptedPackage").read()
    head = " ".join(f"{b:02x}" for b in via_msoffcrypto[:8])
    print(f"EncryptedPackage (msoffcrypto read): starts {head}")
    if via_msoffcrypto[:4] == b"\x04\x00\x04\x00":
        print("    ^ that is EncryptionInfo's version header, not the package")

    try:
        with encrypted.open("rb") as fh:
            office = msoffcrypto.OfficeFile(fh)
            office.load_key(password="s3cret")
            office.decrypt(io.BytesIO())
    except Exception as exc:  # noqa: BLE001 - the point is to show what it raises
        print(f"round trip                       : {type(exc).__name__}: {exc}")
    else:
        print("round trip                       : succeeded (upstream has been fixed)")
        return 1

    print("\nverdict: the two readers disagree about which stream is which -> malformed container")
    print("our own writer round-trips cleanly:")
    blob = F.make_encrypted_ooxml(plain)
    with io.BytesIO(blob) as fh:
        office = msoffcrypto.OfficeFile(fh)
        office.load_key(password=F.SAMPLE_PASSWORD, verify_password=True)
        out = io.BytesIO()
        office.decrypt(out, verify_integrity=True)
    print(f"    fpr.testing.ooxml_agile -> msoffcrypto: identical = {out.getvalue() == plain}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
