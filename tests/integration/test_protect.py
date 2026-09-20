"""Adding protection to a file that has none.

The inverse of the rest of this tool, and the more dangerous direction: a
generated password is the only copy that will ever exist, and this tool
explicitly refuses to recover it. So the invariants here are stricter than for
removal -- the original is never touched, and the output is verified by opening
it with the password before success is reported.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fpr import ProtectOptions, Secret, inspect, passwords, protect
from fpr.errors import FprError
from fpr.types import Protection

from ..conftest import SAMPLE_PASSWORD


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_protecting_a_pdf_produces_a_file_that_needs_the_password(pdf_plain: Path) -> None:
    before = _digest(pdf_plain)

    result = protect(pdf_plain, Secret.from_text(SAMPLE_PASSWORD))

    assert result.output.exists()
    assert inspect(result.output).protection is Protection.USER_PASSWORD
    assert _digest(pdf_plain) == before, "the original was modified"


def test_protecting_a_zip_produces_a_file_that_needs_the_password(zip_plain: Path) -> None:
    before = _digest(zip_plain)

    result = protect(zip_plain, Secret.from_text(SAMPLE_PASSWORD))

    assert inspect(result.output).protection is Protection.USER_PASSWORD
    assert _digest(zip_plain) == before, "the original was modified"


def test_the_protected_file_round_trips_back_to_the_original_content(pdf_plain: Path) -> None:
    """Verification is the point: the content must survive being locked."""
    from fpr import RemovalOptions, remove

    protected = protect(pdf_plain, Secret.from_text(SAMPLE_PASSWORD)).output
    recovered = remove(
        protected,
        Secret.from_text(SAMPLE_PASSWORD),
        RemovalOptions(output=protected.parent / "recovered.pdf"),
    )

    assert recovered.verification["pages"] == "3"


def test_a_generated_password_opens_the_file_it_protected(pdf_plain: Path) -> None:
    secret = passwords.generate()
    with secret.expose() as text:
        generated = text

    result = protect(pdf_plain, secret)

    from fpr import RemovalOptions, remove

    remove(
        result.output,
        Secret.from_text(generated),
        RemovalOptions(output=result.output.parent / "opened.pdf"),
    )


def test_protecting_an_already_encrypted_file_is_refused(pdf_encrypted: Path) -> None:
    """Double-encrypting silently would make the first password unrecoverable."""
    with pytest.raises(FprError) as caught:
        protect(pdf_encrypted, Secret.from_text(SAMPLE_PASSWORD))

    assert "already" in str(caught.value).lower()


def test_protect_refuses_to_write_over_its_own_source(pdf_plain: Path) -> None:
    """There is no in-place mode: losing the only key would destroy the file."""
    with pytest.raises(FprError):
        protect(
            pdf_plain,
            Secret.from_text(SAMPLE_PASSWORD),
            ProtectOptions(output=pdf_plain),
        )


def test_verification_evidence_is_reported(pdf_plain: Path) -> None:
    result = protect(pdf_plain, Secret.from_text(SAMPLE_PASSWORD))

    assert result.verification["encrypted"] == "true"
    assert result.algorithm
    assert result.protection_applied is Protection.USER_PASSWORD


def test_an_unsupported_format_says_so_rather_than_failing_obscurely(docx_plain: Path) -> None:
    with pytest.raises(FprError) as caught:
        protect(docx_plain, Secret.from_text(SAMPLE_PASSWORD))

    message = str(caught.value).lower()
    assert "not supported" in message or "cannot" in message
