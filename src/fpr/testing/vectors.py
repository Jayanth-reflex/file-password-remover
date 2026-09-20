"""Export the generated fixtures as a language-neutral test-vector corpus.

The iOS and Android ports do not share code with this package -- they cannot,
because the engine is Python and the adapters lean on qpdf. What they *can*
share is evidence. This module writes every fixture to disk next to a JSON
manifest describing what each file is, which password opens it, and what a
correct implementation must find inside it.

A Swift or Kotlin test suite that reads this manifest is proved against files
built from the format specifications by an independent implementation, rather
than against a mirror of itself.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from . import fixtures as F

__all__ = ["Vector", "export_corpus", "CORPUS_VERSION"]

CORPUS_VERSION = 1


def _members(pairs: tuple[tuple[str, bytes], ...]) -> list[dict[str, object]]:
    """Describe archive members by name, size and plaintext digest.

    The digest is the point: a port that reports success without actually
    decrypting the payload fails here, where a "did it throw?" check passes.
    """
    return [
        {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in pairs
    ]


# Plaintext of the ZIP/7z members, so a port can assert on decrypted content
# rather than merely on "no exception was thrown".
_ZIP_MEMBERS = _members(F._ZIP_MEMBERS)
_MIXED_MEMBERS = _members((("public.txt", b"not secret\n" * 10), ("private.txt", b"secret\n" * 10)))


@dataclass(frozen=True)
class Vector:
    """One file in the corpus, plus what a correct port must conclude."""

    id: str
    file: str
    format: str
    protection: str
    removable: bool
    password: str | None = None
    notes: str = ""
    expect: dict[str, object] = field(default_factory=dict)


def _pdf_vectors() -> list[tuple[Vector, bytes]]:
    out: list[tuple[Vector, bytes]] = []
    out.append(
        (
            Vector(
                id="pdf-plain",
                file="pdf/pdf-plain.pdf",
                format="pdf",
                protection="none",
                removable=False,
                notes="Not encrypted. A port must report 'none', not fail.",
                expect={"pages": 3},
            ),
            F.make_pdf(),
        )
    )
    revisions: tuple[tuple[Literal[2, 3, 4, 5, 6], str], ...] = (
        (2, "rc4-40"),
        (3, "rc4-128"),
        (4, "aes-128"),
        (5, "aes-256-r5"),
        (6, "aes-256-r6"),
    )
    for revision, label in revisions:
        out.append(
            (
                Vector(
                    id=f"pdf-{label}-user",
                    file=f"pdf/pdf-{label}-user.pdf",
                    format="pdf",
                    protection="user-password",
                    removable=True,
                    password=F.SAMPLE_PASSWORD,
                    notes=f"Standard security handler, R={revision}.",
                    expect={"pages": 3, "revision": revision},
                ),
                F.make_pdf(
                    F.PdfSpec(user=F.SAMPLE_PASSWORD, owner=F.OWNER_PASSWORD, revision=revision)
                ),
            )
        )
    out.append(
        (
            Vector(
                id="pdf-owner-restrictions",
                file="pdf/pdf-owner-restrictions.pdf",
                format="pdf",
                protection="owner-restrictions",
                removable=False,
                notes=(
                    "Empty user password, printing/extraction denied. Clearing these "
                    "flags without the owner password is a bypass: a port MUST refuse."
                ),
                expect={"pages": 3},
            ),
            F.make_pdf(
                F.PdfSpec(owner=F.OWNER_PASSWORD, revision=6, deny_print=True, deny_extract=True)
            ),
        )
    )
    return out


def _ooxml_vectors() -> list[tuple[Vector, bytes]]:
    out: list[tuple[Vector, bytes]] = []
    for kind, builder in (("docx", F.make_docx), ("xlsx", F.make_xlsx), ("pptx", F.make_pptx)):
        out.append(
            (
                Vector(
                    id=f"ooxml-{kind}-agile",
                    file=f"ooxml/ooxml-{kind}-agile.{kind}",
                    format="ooxml",
                    protection="user-password",
                    removable=True,
                    password=F.SAMPLE_PASSWORD,
                    notes=(
                        "ECMA-376 agile encryption in a CFB container. AES-256-CBC, "
                        f"SHA-512, {F.FIXTURE_SPIN_COUNT} spins."
                    ),
                    expect={"spin_count": F.FIXTURE_SPIN_COUNT, "inner_zip": True},
                ),
                F.make_encrypted_ooxml(builder()),
            )
        )
    out.append(
        (
            Vector(
                id="ooxml-docx-plain",
                file="ooxml/ooxml-docx-plain.docx",
                format="ooxml",
                protection="none",
                removable=False,
                notes="An ordinary OOXML package: a ZIP, not a CFB container.",
                expect={"inner_zip": True},
            ),
            F.make_docx(),
        )
    )
    out.append(
        (
            Vector(
                id="ooxml-docx-restricted",
                file="ooxml/ooxml-docx-restricted.docx",
                format="ooxml",
                protection="owner-restrictions",
                removable=False,
                notes="documentProtection in settings.xml. Not encryption; refuse to strip it.",
            ),
            F.make_docx_restricted(),
        )
    )
    return out


def _zip_vectors() -> list[tuple[Vector, bytes]]:
    out: list[tuple[Vector, bytes]] = []
    out.append(
        (
            Vector(
                id="zip-plain",
                file="zip/zip-plain.zip",
                format="zip",
                protection="none",
                removable=False,
                expect={"members": _ZIP_MEMBERS},
            ),
            F.make_zip_plain(),
        )
    )
    for bits in (128, 192, 256):
        out.append(
            (
                Vector(
                    id=f"zip-aes{bits}",
                    file=f"zip/zip-aes{bits}.zip",
                    format="zip",
                    protection="user-password",
                    removable=True,
                    password=F.SAMPLE_PASSWORD,
                    notes=f"WinZip AE-2, AES-{bits}, PBKDF2-HMAC-SHA1 1000 iterations.",
                    expect={"members": _ZIP_MEMBERS, "aes_bits": bits},
                ),
                F.make_zip_aes(bits=bits),
            )
        )
    out.append(
        (
            Vector(
                id="zip-zipcrypto",
                file="zip/zip-zipcrypto.zip",
                format="zip",
                protection="user-password",
                removable=True,
                password=F.SAMPLE_PASSWORD,
                notes="Legacy PKWARE ZipCrypto stream cipher.",
                expect={"members": _ZIP_MEMBERS},
            ),
            F.make_zip_zipcrypto(),
        )
    )
    out.append(
        (
            Vector(
                id="zip-mixed",
                file="zip/zip-mixed.zip",
                format="zip",
                protection="user-password",
                removable=True,
                password=F.SAMPLE_PASSWORD,
                notes="One encrypted entry, one not. Both must survive the round trip.",
                expect={"members": _MIXED_MEMBERS},
            ),
            F.make_zip_mixed(),
        )
    )
    return out


def _sevenzip_vectors() -> list[tuple[Vector, bytes]]:
    """7-Zip vectors, or nothing when the optional extra is absent.

    ``py7zr`` is an opt-in extra (ADR-0006), so a default install must still be
    able to build its own fixtures. The ports read the manifest rather than a
    hardcoded list, so they simply see no 7-Zip vectors to check.
    """
    try:
        import py7zr  # noqa: F401
    except ImportError:
        return []

    return [
        (
            Vector(
                id="7z-encrypted-data",
                file="sevenzip/7z-encrypted-data.7z",
                format="7z",
                protection="user-password",
                removable=True,
                password=F.SAMPLE_PASSWORD,
                notes="AES-256, plaintext header: names visible, contents encrypted.",
                expect={"members": _ZIP_MEMBERS, "header_encrypted": False},
            ),
            F.make_sevenzip(),
        ),
        (
            Vector(
                id="7z-encrypted-header",
                file="sevenzip/7z-encrypted-header.7z",
                format="7z",
                protection="user-password",
                removable=True,
                password=F.SAMPLE_PASSWORD,
                notes="Header encrypted too: the file list itself needs the password.",
                expect={"members": _ZIP_MEMBERS, "header_encrypted": True},
            ),
            F.make_sevenzip(encrypt_header=True),
        ),
    ]


def _legacy_office_vectors() -> list[tuple[Vector, bytes]]:
    return [
        (
            Vector(
                id="legacy-doc-encrypted",
                file="legacy/legacy-doc-encrypted.doc",
                format="legacy-office",
                protection="user-password",
                removable=False,
                notes=(
                    "Word 97-2003 CFB container with fEncrypted set. Detection only: "
                    "no open tooling produces a genuinely decryptable RC4 payload, so a "
                    "port must DETECT this and report it as unsupported rather than "
                    "claim it can decrypt it."
                ),
            ),
            F.make_legacy_doc(encrypted=True),
        ),
        (
            Vector(
                id="legacy-doc-plain",
                file="legacy/legacy-doc-plain.doc",
                format="legacy-office",
                protection="none",
                removable=False,
                notes="Same container, fEncrypted clear.",
            ),
            F.make_legacy_doc(encrypted=False),
        ),
    ]


def _damaged_vectors() -> list[tuple[Vector, bytes]]:
    return [
        (
            Vector(
                id="damaged-pdf-truncated",
                file="damaged/damaged-pdf-truncated.pdf",
                format="pdf",
                protection="unknown",
                removable=False,
                notes="Chopped short. Must fail cleanly, not crash and not half-write output.",
            ),
            F.truncate(F.make_pdf(F.PdfSpec(user=F.SAMPLE_PASSWORD))),
        ),
        (
            Vector(
                id="damaged-not-an-archive",
                file="damaged/damaged-not-an-archive.zip",
                format="zip",
                protection="unknown",
                removable=False,
                notes="Extension says ZIP, bytes disagree.",
            ),
            F.NOT_AN_ARCHIVE,
        ),
    ]


def export_corpus(dest: Path) -> Path:
    """Write every vector plus ``manifest.json`` into *dest*; return the manifest."""
    dest = Path(dest)
    entries: list[tuple[Vector, bytes]] = [
        *_pdf_vectors(),
        *_ooxml_vectors(),
        *_zip_vectors(),
        *_sevenzip_vectors(),
        *_legacy_office_vectors(),
        *_damaged_vectors(),
    ]

    for vector, data in entries:
        target = dest / vector.file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    manifest = {
        "version": CORPUS_VERSION,
        "generator": "fpr.testing.vectors",
        "passwords": {
            "correct": F.SAMPLE_PASSWORD,
            "wrong": F.WRONG_PASSWORD,
            "owner": F.OWNER_PASSWORD,
        },
        "vectors": [asdict(vector) for vector, _ in entries],
    }
    manifest_path = dest / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest_path
