"""Encrypted Office documents, decrypted and proved intact.

The fixtures are produced by :mod:`fpr.testing.ooxml_agile`, an implementation
of the *encryption* side written from [MS-OFFCRYPTO]; the code under test
decrypts with msoffcrypto-tool. Two implementations, one file format.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from fpr import Secret, inspect, remove
from fpr.errors import CorruptFileError, IncorrectPasswordError, PolicyRefusedError
from fpr.types import Protection

from ..conftest import SAMPLE_PASSWORD, WRONG_PASSWORD


def _parts(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


@pytest.mark.parametrize("fixture", ["docx_encrypted", "xlsx_encrypted", "pptx_encrypted"])
def test_decrypts_every_office_type(fixture: str, request: pytest.FixtureRequest) -> None:
    path = request.getfixturevalue(fixture)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert result.protection_removed is Protection.USER_PASSWORD
    assert result.verification["encrypted"] == "false"
    assert result.verification["content_types_present"] == "true"
    assert result.output.read_bytes()[:4] == b"PK\x03\x04"


def test_every_part_survives_byte_for_byte(docx_encrypted: Path) -> None:
    from fpr.testing import fixtures as F

    expected = _parts_from_bytes(F.make_docx())
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(docx_encrypted, pw)
    assert _parts(result.output) == expected


def _parts_from_bytes(blob: bytes) -> dict[str, bytes]:
    import io

    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def test_wrong_password_is_rejected_by_the_verifier(docx_encrypted: Path) -> None:
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError) as exc:
        remove(docx_encrypted, pw)
    assert exc.value.exit_code == 3


def test_original_is_untouched(docx_encrypted: Path) -> None:
    before = docx_encrypted.read_bytes()
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(docx_encrypted, pw)
    assert docx_encrypted.read_bytes() == before


def test_tampered_payload_is_reported_as_damage_not_a_wrong_password(write) -> None:
    """A correct password plus a mangled payload must not say 'wrong password'."""
    from fpr.testing import fixtures as F

    blob = bytearray(F.make_encrypted_ooxml(F.make_docx()))
    # Flip bytes well inside the encrypted package, past the CFB header and
    # directory, so the HMAC fails but the container still parses.
    for offset in range(3000, 3064):
        blob[offset] ^= 0xFF
    path = write("tampered.docx", bytes(blob))
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(CorruptFileError) as exc:
        remove(path, pw)
    assert "integrity" in exc.value.message.lower() or "decrypt" in exc.value.message.lower()


def test_editing_restrictions_are_refused(docx_restricted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(PolicyRefusedError) as exc:
        remove(docx_restricted, pw)
    assert exc.value.exit_code == 10
    assert "bypass" in exc.value.message


def test_unencrypted_package_is_reported_as_not_protected(docx_plain: Path) -> None:
    assert inspect(docx_plain).protection is Protection.NONE
