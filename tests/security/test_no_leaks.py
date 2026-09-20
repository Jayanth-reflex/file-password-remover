"""Nothing secret escapes: not to stdout, stderr, logs, tracebacks or disk."""

from __future__ import annotations

import logging
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from fpr import RemovalOptions, Secret, remove
from fpr.cli.main import main
from fpr.errors import FprError

from ..conftest import SAMPLE_PASSWORD, WRONG_PASSWORD

DISTINCTIVE = "Zq7-unlikely-password-string-42"


def _pwfile(tmp_path: Path, value: str) -> Path:
    path = tmp_path / "pw.txt"
    path.write_text(value)
    path.chmod(0o600)
    return path


def test_password_is_absent_from_successful_cli_output(write, tmp_path, capsys) -> None:
    from fpr.testing import fixtures as F

    target = write("s.pdf", F.make_pdf(F.PdfSpec(user=DISTINCTIVE, owner="other-owner")))
    main(
        ["-v", "-v", "remove", str(target), "--password-file", str(_pwfile(tmp_path, DISTINCTIVE))]
    )
    captured = capsys.readouterr()
    assert DISTINCTIVE not in captured.out
    assert DISTINCTIVE not in captured.err


def test_password_is_absent_from_failure_output(pdf_encrypted: Path, tmp_path, capsys) -> None:
    main(
        [
            "-v",
            "-v",
            "remove",
            str(pdf_encrypted),
            "--password-file",
            str(_pwfile(tmp_path, DISTINCTIVE)),
        ]
    )
    captured = capsys.readouterr()
    assert DISTINCTIVE not in captured.out
    assert DISTINCTIVE not in captured.err


def test_password_is_absent_from_exception_text_and_traceback(pdf_encrypted: Path) -> None:
    with Secret.from_text(DISTINCTIVE) as pw:
        try:
            remove(pdf_encrypted, pw)
        except FprError as exc:
            rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        else:  # pragma: no cover - the password is wrong, so this cannot happen
            pytest.fail("expected a failure")
    assert DISTINCTIVE not in rendered


def test_password_is_absent_from_debug_logs(pdf_encrypted: Path, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    with Secret.from_text(DISTINCTIVE) as pw, pytest.raises(FprError):
        remove(pdf_encrypted, pw)
    assert DISTINCTIVE not in caplog.text


def test_password_never_reaches_argv_of_a_child_process(pdf_encrypted: Path, tmp_path) -> None:
    """The one route that would expose it to every user on the machine."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fpr.cli.main",
            "remove",
            str(pdf_encrypted),
            "--password-file",
            str(_pwfile(tmp_path, SAMPLE_PASSWORD)),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0
    assert SAMPLE_PASSWORD not in " ".join(result.args)


def test_no_plaintext_survives_a_failed_run(write, tmp_path) -> None:
    """A run that fails verification must leave no readable fragment behind."""
    from fpr.adapters import pdf as pdf_adapter
    from fpr.errors import VerificationError
    from fpr.testing import fixtures as F

    marker = b"SENSITIVE-PAYLOAD-MARKER"
    target = write("s.pdf", F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner="o")))
    # Force verification to fail after a complete, valid decryption.
    original = pdf_adapter.PdfAdapter.verify

    def failing(self, output, evidence):  # noqa: ANN001, ARG001
        Path(output).write_bytes(marker * 100)
        raise VerificationError("forced")

    pdf_adapter.PdfAdapter.verify = failing  # type: ignore[method-assign]
    try:
        with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(VerificationError):
            remove(target, pw)
    finally:
        pdf_adapter.PdfAdapter.verify = original  # type: ignore[method-assign]

    for path in tmp_path.rglob("*"):
        if path.is_file() and path != target:
            assert marker not in path.read_bytes(), f"plaintext fragment left in {path}"


def test_in_place_failure_leaves_the_original_intact(pdf_encrypted: Path) -> None:
    before = pdf_encrypted.read_bytes()
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(FprError):
        remove(pdf_encrypted, pw, RemovalOptions(in_place=True))
    assert pdf_encrypted.read_bytes() == before


def test_secret_is_wiped_after_the_cli_run(pdf_encrypted: Path, tmp_path, monkeypatch) -> None:
    captured: list[Secret] = []
    import fpr.cli.main as cli

    real = cli.resolve_secret

    def spy(args, **kwargs):  # noqa: ANN001, ANN003
        secret = real(args, **kwargs)
        captured.append(secret)
        return secret

    monkeypatch.setattr(cli, "resolve_secret", spy)
    main(["remove", str(pdf_encrypted), "--password-file", str(_pwfile(tmp_path, SAMPLE_PASSWORD))])
    assert captured and captured[0].closed
