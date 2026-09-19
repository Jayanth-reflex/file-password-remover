"""End-to-end PDF removal, including the restriction-removal policy."""

from __future__ import annotations

from pathlib import Path

import pikepdf
import pytest

from fpr import RemovalOptions, Secret, remove
from fpr.errors import IncorrectPasswordError, PolicyRefusedError, VerificationError
from fpr.types import Protection

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD, WRONG_PASSWORD


def _source_digest(path: Path, password: str) -> tuple[int, bytes]:
    from fpr.adapters.pdf import page_content_bytes

    with pikepdf.open(path, password=password) as pdf:
        return len(pdf.pages), b"".join(page_content_bytes(p) for p in pdf.pages)


def test_decrypts_and_keeps_the_content(pdf_encrypted: Path) -> None:
    pages, content = _source_digest(pdf_encrypted, SAMPLE_PASSWORD)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)

    assert result.output.name == "secret-unprotected.pdf"
    assert result.protection_removed is Protection.USER_PASSWORD
    assert result.verification["encrypted"] == "false"
    from fpr.adapters.pdf import page_content_bytes

    with pikepdf.open(result.output) as out:
        assert not out.is_encrypted
        assert len(out.pages) == pages
        assert b"".join(page_content_bytes(p) for p in out.pages) == content


def test_encrypted_and_restricted_is_reported_as_both(write) -> None:
    from fpr.testing import fixtures as F

    path = write(
        "both.pdf",
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD, deny_print=True)),
    )
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert result.protection_removed is Protection.BOTH
    with pikepdf.open(result.output) as out:
        assert out.allow.print_highres is True


def test_original_is_left_untouched(pdf_encrypted: Path) -> None:
    before = pdf_encrypted.read_bytes()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        remove(pdf_encrypted, pw)
    assert pdf_encrypted.read_bytes() == before


def test_owner_password_also_decrypts(pdf_encrypted: Path) -> None:
    with Secret.from_text(OWNER_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    with pikepdf.open(result.output) as out:
        assert not out.is_encrypted


def test_wrong_password_is_reported_exactly(pdf_encrypted: Path) -> None:
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError) as exc:
        remove(pdf_encrypted, pw)
    assert exc.value.exit_code == 3
    assert not (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


def test_metadata_is_preserved(pdf_encrypted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    with pikepdf.open(result.output) as out, out.open_metadata() as meta:
        assert meta["dc:title"] == "File Password Remover test fixture"


@pytest.mark.parametrize("revision", [2, 3, 4, 5, 6])
def test_every_supported_revision(write, revision: int) -> None:
    from fpr.testing import fixtures as F

    path = write(
        f"r{revision}.pdf",
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD, revision=revision)),
    )
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert result.algorithm
    with pikepdf.open(result.output) as out:
        assert not out.is_encrypted
        assert len(out.pages) == 3


def test_rc4_revisions_warn_about_the_obsolete_cipher(write) -> None:
    from fpr.testing import fixtures as F

    path = write("rc4.pdf", F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, revision=3)))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert any("RC4" in w for w in result.warnings)


# ------------------------------------------------- restriction-only policy
def test_restriction_only_pdf_is_refused_without_the_flag(pdf_restricted: Path) -> None:
    with Secret.from_text(OWNER_PASSWORD) as pw, pytest.raises(PolicyRefusedError) as exc:
        remove(pdf_restricted, pw)
    assert exc.value.exit_code == 10


def test_restriction_removal_requires_the_owner_password(pdf_restricted: Path) -> None:
    options = RemovalOptions(allow_restriction_removal=True)
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(pdf_restricted, pw, options)


def test_restrictions_are_cleared_with_the_owner_password(pdf_restricted: Path) -> None:
    options = RemovalOptions(allow_restriction_removal=True)
    with Secret.from_text(OWNER_PASSWORD) as pw:
        result = remove(pdf_restricted, pw, options)
    assert result.protection_removed is Protection.OWNER_RESTRICTIONS
    with pikepdf.open(result.output) as out:
        assert not out.is_encrypted
        assert out.allow.extract is True
        assert out.allow.print_highres is True


def test_restriction_removal_is_announced_in_the_warnings(pdf_restricted: Path) -> None:
    with Secret.from_text(OWNER_PASSWORD) as pw:
        result = remove(pdf_restricted, pw, RemovalOptions(allow_restriction_removal=True))
    assert any("owner password" in w for w in result.warnings)


def test_verification_failure_discards_the_output(pdf_encrypted: Path, monkeypatch) -> None:
    """If the written file does not match the input, nothing is published."""
    from fpr.adapters import pdf as pdf_adapter

    real = pdf_adapter._capture_expectations
    calls = {"n": 0}

    def lying(pdf):  # the second call is the read-back during verify
        calls["n"] += 1
        out = real(pdf)
        if calls["n"] > 1:
            out["pages"] = "999"
        return out

    monkeypatch.setattr(pdf_adapter, "_capture_expectations", lying)
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(VerificationError) as exc:
        remove(pdf_encrypted, pw)
    assert exc.value.exit_code == 9
    assert not (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


# --------------------------------------------- the empty-owner-password trap
def test_empty_owner_password_is_reported_as_unenforceable(write) -> None:
    """user="pw", owner="" is a real and common shape.

    qpdf opens such a file with the *empty owner password*, which means every
    PDF tool on earth can read and re-save it. Detection has no way to see the
    separate open password, so it must describe what it can prove rather than
    claim the document is strongly protected.
    """
    from fpr import inspect
    from fpr.testing import fixtures as F

    path = write("weak.pdf", F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner="")))
    d = inspect(path)
    assert "owner password is empty" in d.detail
    assert "not enforceable" in d.detail


def test_empty_owner_password_still_decrypts_with_the_real_open_password(write) -> None:
    """Holding the user password is authorisation, even when the owner's is empty."""
    from fpr.testing import fixtures as F

    path = write("weak.pdf", F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner="")))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw, RemovalOptions(allow_restriction_removal=True))
    assert result.protection_removed is Protection.USER_PASSWORD
    with pikepdf.open(result.output) as out:
        assert not out.is_encrypted


def test_restriction_only_file_never_opens_with_a_guessed_password(pdf_restricted: Path) -> None:
    """The bypass this tool exists to refuse: qpdf will not let a wrong password in."""
    import pikepdf as _pikepdf

    with pytest.raises(_pikepdf.PasswordError):
        _pikepdf.open(pdf_restricted, password=WRONG_PASSWORD)
