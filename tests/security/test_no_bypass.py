"""Abuse cases. Each of these is something the tool must refuse to do."""

from __future__ import annotations

import string
from pathlib import Path

import pytest

from fpr import RemovalOptions, Secret, inspect, remove
from fpr.errors import IncorrectPasswordError, PolicyRefusedError
from fpr.types import Removability

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD


def test_no_password_guessing_helper_exists() -> None:
    """There must be no API that tries candidate passwords.

    A code-level check, because the most likely way this project turns into a
    cracker is someone adding a helpful "try these" loop.
    """
    import fpr
    from fpr import batch, engine, registry

    banned = {"crack", "bruteforce", "brute_force", "wordlist", "dictionary_attack", "guess"}
    for module in (fpr, engine, batch, registry):
        names = {name.lower() for name in dir(module)}
        assert not (names & banned), f"{module.__name__} exposes {names & banned}"


def test_a_wrong_password_is_never_retried(pdf_encrypted: Path, monkeypatch) -> None:
    """One attempt per invocation. No fallbacks, no empty-password retry."""
    import pikepdf

    attempts: list[str] = []
    real_open = pikepdf.open

    def counting(*args, **kwargs):  # noqa: ANN002, ANN003
        if "password" in kwargs:
            attempts.append(kwargs["password"])
        return real_open(*args, **kwargs)

    monkeypatch.setattr(pikepdf, "open", counting)
    with Secret.from_text("definitely-wrong"), pytest.raises(IncorrectPasswordError):
        with Secret.from_text("definitely-wrong") as pw:
            remove(pdf_encrypted, pw)
    assert attempts == ["definitely-wrong"]


def test_restriction_stripping_without_the_owner_password_is_refused(pdf_restricted: Path) -> None:
    """The exact thing every 'free PDF unlocker' does, and this tool will not."""
    options = RemovalOptions(allow_restriction_removal=True)
    for candidate in ("", "password", "1234", "admin", OWNER_PASSWORD[::-1]):
        if not candidate:
            continue
        with Secret.from_text(candidate) as pw, pytest.raises(IncorrectPasswordError):
            remove(pdf_restricted, pw, options)
    assert pdf_restricted.parent.joinpath("restricted-unprotected.pdf").exists() is False


def test_restriction_removal_is_off_by_default(pdf_restricted: Path) -> None:
    with Secret.from_text(OWNER_PASSWORD) as pw, pytest.raises(PolicyRefusedError):
        remove(pdf_restricted, pw)


def test_office_editing_restrictions_are_never_stripped(docx_restricted: Path) -> None:
    for allow in (False, True):
        with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(PolicyRefusedError):
            remove(docx_restricted, pw, RemovalOptions(allow_restriction_removal=allow))


def test_legacy_office_is_gated_behind_experimental(write) -> None:
    """An untested code path must not be reachable by accident."""
    from fpr.adapters.base import AdapterOptions
    from fpr.adapters.legacy_office import LegacyOfficeAdapter

    adapter = LegacyOfficeAdapter()
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(PolicyRefusedError) as exc:
        adapter.remove(Path("x.doc"), Path("y.doc"), pw, AdapterOptions(experimental=False))
    assert "experimental" in exc.value.message


def test_drm_is_reported_as_permanently_out_of_scope(write) -> None:
    """A PDF encrypted to a certificate is not password protection."""
    header = b"%PDF-1.7\n" + b"/Filter /Adobe.PubSec /SubFilter /adbe.pkcs7.s4\n" * 4
    path = write("cert.pdf", header + b"\n%%EOF\n")
    d = inspect(path)
    assert d.removability is Removability.UNSUPPORTED
    assert "private key" in d.detail


def test_engine_never_opens_a_pdf_with_an_empty_password_to_decrypt(pdf_restricted) -> None:
    """The empty-password open used for *detection* must never write anything."""
    import pikepdf

    from fpr.adapters.pdf import _opens_without_password

    assert _opens_without_password(pdf_restricted) is True
    # ...and the file is untouched by that check.
    with pikepdf.open(pdf_restricted) as pdf:
        assert pdf.is_encrypted


def test_password_charset_is_not_restricted(write) -> None:
    """Refusing exotic characters would push users to weaker passwords."""
    from fpr.testing import fixtures as F

    exotic = "".join(string.punctuation) + " spaces ünïcode 日本語 🔐"
    path = write("exotic.pdf", F.make_pdf(F.PdfSpec(user=exotic, owner="other")))
    with Secret.from_text(exotic) as pw:
        result = remove(path, pw)
    assert result.verification["encrypted"] == "false"
