"""Legacy Office 97-2003: detection is tested, decryption is gated.

The split is deliberate and is the honest position: identifying one of these
containers needs no sample we cannot build, so that is covered here. Producing
a genuinely RC4-encrypted Word or Excel binary document is not possible with
open tooling, so the decryption path has no fixture, is off by default, and
says so wherever it surfaces.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fpr import RemovalOptions, Secret, inspect, remove
from fpr.errors import PolicyRefusedError
from fpr.registry import adapter_for
from fpr.types import FormatId, Protection, Removability

from ..conftest import SAMPLE_PASSWORD


def test_claimed_by_the_legacy_adapter_not_the_ooxml_one(legacy_doc_encrypted: Path) -> None:
    assert adapter_for(legacy_doc_encrypted).format_id is FormatId.LEGACY_OFFICE


def test_encrypted_legacy_document_is_detected(legacy_doc_encrypted: Path) -> None:
    d = inspect(legacy_doc_encrypted)
    assert d.protection is Protection.USER_PASSWORD
    assert d.removability is Removability.REMOVABLE
    assert "Word" in d.format_name


def test_detection_says_the_support_is_experimental(legacy_doc_encrypted: Path) -> None:
    assert "EXPERIMENTAL" in inspect(legacy_doc_encrypted).detail


def test_unencrypted_legacy_document_is_reported_as_such(legacy_doc_plain: Path) -> None:
    d = inspect(legacy_doc_plain)
    assert d.protection is Protection.NONE
    assert d.removability is Removability.NOT_PROTECTED


def test_decryption_is_refused_unless_experimental_is_requested(
    legacy_doc_encrypted: Path,
) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(PolicyRefusedError) as exc:
        remove(legacy_doc_encrypted, pw)
    assert exc.value.exit_code == 10
    assert "experimental" in exc.value.message


def test_with_experimental_it_attempts_and_fails_cleanly(legacy_doc_encrypted: Path) -> None:
    """The fixture is not really decryptable; the failure must still be clean.

    "Clean" means: a typed error with an exit code, and no output file left on
    disk claiming success.
    """
    from fpr.errors import FprError

    options = RemovalOptions(experimental=True)
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(FprError):
        remove(legacy_doc_encrypted, pw, options)
    assert not (legacy_doc_encrypted.parent / "legacy-unprotected.doc").exists()
