"""Identification is by content, and the report says what was found."""

from __future__ import annotations

from pathlib import Path

import pytest

from fpr import inspect
from fpr.errors import CorruptFileError, UnsupportedFormatError
from fpr.registry import adapter_for
from fpr.types import FormatId, Protection, Removability


def test_pdf_encrypted_is_reported_without_a_password(pdf_encrypted: Path) -> None:
    d = inspect(pdf_encrypted)
    assert d.format_id is FormatId.PDF
    assert d.protection is Protection.USER_PASSWORD
    assert d.removability is Removability.REMOVABLE
    assert "AES-256" in (d.algorithm or "")


def test_pdf_plain_is_reported_as_unprotected(pdf_plain: Path) -> None:
    d = inspect(pdf_plain)
    assert d.protection is Protection.NONE
    assert d.removability is Removability.NOT_PROTECTED


def test_pdf_restriction_only_is_flagged_as_owner_password_required(pdf_restricted: Path) -> None:
    d = inspect(pdf_restricted)
    assert d.protection is Protection.OWNER_RESTRICTIONS
    assert d.removability is Removability.REMOVABLE_WITH_OWNER_PASSWORD
    assert "owner password" in d.detail


def test_encrypted_docx_is_an_ole_container_not_a_zip(docx_encrypted: Path) -> None:
    assert docx_encrypted.read_bytes()[:2] == b"\xd0\xcf"
    d = inspect(docx_encrypted)
    assert d.format_id is FormatId.OOXML
    assert d.protection is Protection.USER_PASSWORD
    assert "agile" in (d.algorithm or "")


def test_restricted_docx_is_refused_by_policy(docx_restricted: Path) -> None:
    d = inspect(docx_restricted)
    assert d.protection is Protection.OWNER_RESTRICTIONS
    assert d.removability is Removability.REFUSED_BY_POLICY
    assert "not encrypted" in d.detail


@pytest.mark.parametrize("fixture", ["zip_aes", "zip_zipcrypto", "zip_mixed"])
def test_encrypted_zips_are_detected(fixture: str, request: pytest.FixtureRequest) -> None:
    path = request.getfixturevalue(fixture)
    d = inspect(path)
    assert d.format_id is FormatId.ZIP
    assert d.protection is Protection.USER_PASSWORD


def test_zip_algorithm_names_the_scheme(zip_aes: Path, zip_zipcrypto: Path) -> None:
    assert "AES-256" in (inspect(zip_aes).algorithm or "")
    assert "ZipCrypto" in (inspect(zip_zipcrypto).algorithm or "")


def test_mixed_zip_reports_the_partial_encryption(zip_mixed: Path) -> None:
    assert "1 of 2" in inspect(zip_mixed).detail


def test_plain_zip_is_not_protected(zip_plain: Path) -> None:
    assert inspect(zip_plain).protection is Protection.NONE


def test_ooxml_adapter_wins_over_zip_for_office_packages(docx_plain: Path) -> None:
    assert adapter_for(docx_plain).format_id is FormatId.OOXML


def test_renaming_a_file_does_not_change_what_it_is(pdf_encrypted: Path) -> None:
    renamed = pdf_encrypted.with_suffix(".zip")
    pdf_encrypted.rename(renamed)
    d = inspect(renamed)
    assert d.format_id is FormatId.PDF
    assert d.extension_mismatch is True


def test_rar_is_named_and_explained(rar_stub: Path) -> None:
    with pytest.raises(UnsupportedFormatError) as exc:
        inspect(rar_stub)
    assert "RAR" in exc.value.message
    assert "licen" in exc.value.message.lower()


def test_png_is_reported_as_having_no_password_protection(png_stub: Path) -> None:
    with pytest.raises(UnsupportedFormatError) as exc:
        inspect(png_stub)
    assert "PNG" in exc.value.message


def test_corrupt_pdf_is_a_corrupt_error_not_a_password_error(pdf_corrupt: Path) -> None:
    with pytest.raises(CorruptFileError) as exc:
        inspect(pdf_corrupt)
    assert "damaged" in (exc.value.remediation or "").lower()


def test_badly_truncated_encrypted_pdf_is_corrupt_not_wrong_password(
    pdf_encrypted_truncated: Path,
) -> None:
    # Reporting "wrong password" for a damaged file sends the user hunting for
    # a typo that does not exist.
    with pytest.raises(CorruptFileError):
        inspect(pdf_encrypted_truncated)


def test_unknown_bytes_report_their_signature(write) -> None:
    path = write("mystery.bin", b"\xde\xad\xbe\xef" * 40)
    with pytest.raises(UnsupportedFormatError) as exc:
        inspect(path)
    assert "de ad be ef" in exc.value.message
