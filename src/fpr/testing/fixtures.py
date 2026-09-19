"""Deterministic, safe sample files for every supported format.

Everything here is generated at test time from code in this repository. No
binary blobs are committed, nothing is downloaded, and no sample contains real
data -- which keeps the repository free of files that a scanner would flag and
free of anyone else's documents.

Each builder returns the *bytes* of a file; the pytest fixtures in
``tests/conftest.py`` write them into a temp directory.
"""

from __future__ import annotations

import io
import warnings
import zipfile
from dataclasses import dataclass
from typing import Literal

from .ooxml_agile import AgileParams, encrypt_agile
from .zipcrypto import ZipEntry, build_zipcrypto_archive

__all__ = [
    "SAMPLE_PASSWORD",
    "WRONG_PASSWORD",
    "OWNER_PASSWORD",
    "PdfSpec",
    "make_pdf",
    "make_docx",
    "make_xlsx",
    "make_pptx",
    "make_docx_restricted",
    "make_encrypted_ooxml",
    "make_zip_plain",
    "make_zip_aes",
    "make_zip_zipcrypto",
    "make_zip_mixed",
    "make_sevenzip",
    "make_legacy_doc",
    "truncate",
    "NOT_AN_ARCHIVE",
    "RAR_STUB",
]

# Sample passwords for generated fixtures. They protect nothing real: the
# files they lock are built by this module and thrown away by the test run.
SAMPLE_PASSWORD = "correct horse battery staple"  # nosec B105
WRONG_PASSWORD = "not the password"  # nosec B105
OWNER_PASSWORD = "owner-only-secret"  # nosec B105

# A fast spin count keeps the Office fixtures usable in a test suite. Real
# documents use 100 000; the code path is identical either way.
FIXTURE_SPIN_COUNT = 1000


# --------------------------------------------------------------------- PDF
@dataclass(frozen=True)
class PdfSpec:
    pages: int = 3
    user: str | None = None
    owner: str | None = None
    revision: Literal[2, 3, 4, 5, 6] = 6
    deny_print: bool = False
    deny_extract: bool = False


def make_pdf(spec: PdfSpec = PdfSpec()) -> bytes:
    """Build a small PDF with real page content, optionally encrypted."""
    import pikepdf

    pdf = pikepdf.new()
    for index in range(spec.pages):
        page = pdf.add_blank_page(page_size=(200, 200))
        # Real content streams, so content digests are meaningful.
        stream = pdf.make_stream(
            f"BT /F1 12 Tf 20 100 Td (Page {index + 1} of {spec.pages}) Tj ET".encode()
        )
        font = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Font,
                Subtype=pikepdf.Name.Type1,
                BaseFont=pikepdf.Name.Helvetica,
            )
        )
        page.Contents = pdf.make_indirect(stream)
        page.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
    with pdf.open_metadata() as meta:
        meta["dc:title"] = "File Password Remover test fixture"

    buf = io.BytesIO()
    if spec.user is None and spec.owner is None:
        pdf.save(buf)
    else:
        # Spell out every flag. pikepdf's default Permissions() denies
        # modify_assembly, which would make an otherwise unrestricted fixture
        # report as "encrypted AND restricted".
        allow = pikepdf.Permissions(
            accessibility=True,
            extract=not spec.deny_extract,
            modify_annotation=True,
            modify_assembly=True,
            modify_form=True,
            modify_other=True,
            print_lowres=not spec.deny_print,
            print_highres=not spec.deny_print,
        )
        encryption = pikepdf.Encryption(
            user=spec.user or "",
            owner=spec.owner or "",
            R=spec.revision,
            allow=allow,
            # R2/R3 predate both AES and encrypted metadata; qpdf refuses
            # either combination outright.
            aes=spec.revision >= 4,
            metadata=spec.revision >= 4,
        )
        with warnings.catch_warnings():
            # R5 is deprecated and qpdf says so. We generate it on purpose:
            # documents using it exist, so the adapter has to handle them.
            warnings.filterwarnings("ignore", message=".*R=5 is deprecated.*")
            pdf.save(buf, encryption=encryption)
    return buf.getvalue()


# ------------------------------------------------------------------- OOXML
_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    "{overrides}</Types>"
)
_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
    'relationships/officeDocument" Target="{target}"/></Relationships>'
)


def _package(parts: dict[str, str], overrides: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES.format(overrides=overrides))
        for name, body in parts.items():
            zf.writestr(name, body)
    return buf.getvalue()


def make_docx(text: str = "File Password Remover fixture document.") -> bytes:
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    return _package(
        {"_rels/.rels": _RELS.format(target="word/document.xml"), "word/document.xml": body},
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.document.main+xml"/>',
    )


def make_docx_restricted() -> bytes:
    """A .docx with editing restrictions but no encryption -- must be refused."""
    settings = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:documentProtection w:edit="readOnly" w:enforcement="1" '
        'w:cryptProviderType="rsaAES" w:cryptAlgorithmClass="hash" '
        'w:cryptAlgorithmSid="14" w:cryptSpinCount="100000" '
        'w:hash="deadbeefdeadbeefdeadbeefdeadbeef" w:salt="cafecafecafecafe"/>'
        "</w:settings>"
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Read-only fixture.</w:t></w:r></w:p></w:body></w:document>"
    )
    return _package(
        {
            "_rels/.rels": _RELS.format(target="word/document.xml"),
            "word/document.xml": body,
            "word/settings.xml": settings,
        },
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.document.main+xml"/>',
    )


def make_xlsx() -> bytes:
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
        "</workbook>"
    )
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>fixture</t></is></c></row>'
        "</sheetData></worksheet>"
    )
    return _package(
        {
            "_rels/.rels": _RELS.format(target="xl/workbook.xml"),
            "xl/workbook.xml": workbook,
            "xl/worksheets/sheet1.xml": sheet,
        },
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.spreadsheetml.sheet.main+xml"/>',
    )


def make_pptx() -> bytes:
    presentation = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'
    )
    return _package(
        {
            "_rels/.rels": _RELS.format(target="ppt/presentation.xml"),
            "ppt/presentation.xml": presentation,
        },
        '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.presentationml.presentation.main+xml"/>',
    )


def make_encrypted_ooxml(
    package: bytes,
    password: str = SAMPLE_PASSWORD,
    *,
    spin_count: int = FIXTURE_SPIN_COUNT,
) -> bytes:
    return encrypt_agile(package, password, params=AgileParams(spin_count=spin_count))


# --------------------------------------------------------------------- ZIP
_ZIP_MEMBERS: tuple[tuple[str, bytes], ...] = (
    ("notes.txt", b"File Password Remover fixture.\n" * 20),
    ("data/values.csv", b"a,b,c\n1,2,3\n" * 40),
    ("data/blob.bin", bytes(range(256)) * 16),
)


def make_zip_plain() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _ZIP_MEMBERS:
            zf.writestr(name, data)
    return buf.getvalue()


def make_zip_aes(password: str = SAMPLE_PASSWORD, *, bits: int = 256) -> bytes:
    import pyzipper

    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.setencryption(pyzipper.WZ_AES, nbits=bits)
        for name, data in _ZIP_MEMBERS:
            zf.writestr(name, data)
    return buf.getvalue()


def make_zip_zipcrypto(password: str = SAMPLE_PASSWORD) -> bytes:
    return build_zipcrypto_archive(
        [ZipEntry(name, data) for name, data in _ZIP_MEMBERS],
        password,
        comment=b"fpr fixture",
    )


def make_zip_mixed(password: str = SAMPLE_PASSWORD) -> bytes:
    """Some entries encrypted, some not -- a real-world shape worth testing."""
    import pyzipper

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.writestr("public.txt", b"not secret\n" * 10)
        zf.setpassword(password.encode("utf-8"))
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr("private.txt", b"secret\n" * 10)
    return buf.getvalue()


# ---------------------------------------------------------------------- 7z
def make_sevenzip(password: str = SAMPLE_PASSWORD, *, encrypt_header: bool = False) -> bytes:
    import py7zr

    buf = io.BytesIO()
    with py7zr.SevenZipFile(
        buf, "w", password=password, header_encryption=encrypt_header
    ) as archive:
        for name, data in _ZIP_MEMBERS:
            archive.writef(io.BytesIO(data), name)
    return buf.getvalue()


# ----------------------------------------------------------- legacy Office
def make_legacy_doc(*, encrypted: bool = True) -> bytes:
    """A minimal Word 97-2003 container, enough to exercise *detection*.

    Only the File Information Block matters for identifying the format and
    reading the ``fEncrypted`` flag: ``wIdent`` = 0xA5EC marks a Word binary
    document, and bit 8 of the flag word at offset 0x0A is set when the
    document is encrypted. ([MS-DOC] 2.5.1.)

    This deliberately does **not** produce a decryptable document. Generating a
    genuine RC4/CryptoAPI-encrypted BIFF8 or Word 97 payload is not possible
    with any open tooling, which is exactly why legacy decryption ships as
    experimental and untested -- see
    :mod:`fpr.adapters.legacy_office`.
    """
    import struct

    from . import cfb

    flags = 0x0001 | (0x0100 if encrypted else 0)
    block = bytearray(1024)
    struct.pack_into("<HHHHH", block, 0, 0xA5EC, 0x00C1, 0x6A62, 0x0409, 0)
    struct.pack_into("<H", block, 0x0A, flags)
    return cfb.write(
        [cfb.stream("WordDocument", bytes(block)), cfb.stream("1Table", b"\x00" * 256)]
    )


# ------------------------------------------------------------- damaged/other
def truncate(data: bytes, keep: float = 0.6) -> bytes:
    """Chop a file short, to exercise the corrupt-file paths."""
    return data[: max(16, int(len(data) * keep))]


NOT_AN_ARCHIVE = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
"""A PNG header: a real file type with no password protection at all."""

RAR_STUB = b"Rar!\x1a\x07\x00" + b"\x00" * 64
"""A RAR signature, to prove the tool names RAR and explains the exclusion."""
