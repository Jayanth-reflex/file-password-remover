"""The command line contract: output, exit codes, and password routes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fpr.cli.main import main
from fpr.errors import ExitCode

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD, WRONG_PASSWORD

CHILD_TIMEOUT = 120
"""Seconds. Generous for a fixture-sized file on a slow hosted runner, and far
short of a CI job limit, so a child that blocks fails this test loudly instead
of hanging the whole matrix."""


def run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run the real installed entry point in a child process.

    In-process calls to ``main`` cover most behaviour, but exit codes, argv
    handling and stdin belong to the process boundary, so those are tested for
    real.

    ``stdin`` is always explicit. Letting the child inherit the test runner's
    descriptor makes the no-TTY tests depend on how the CI runner was started:
    if fd 0 happens to be a console, the tool correctly decides it may prompt,
    and then blocks forever on input nobody is going to type.
    """
    argv = [sys.executable, "-m", "fpr.cli.main", *args]
    if stdin is None:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=CHILD_TIMEOUT,
        )
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT,
    )


# ------------------------------------------------------------------ inspect
def test_inspect_needs_no_password(pdf_encrypted: Path, capsys) -> None:
    assert main(["inspect", str(pdf_encrypted)]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "user-password" in out
    assert "AES-256" in out


def test_inspect_json_is_valid(pdf_encrypted: Path, capsys) -> None:
    main(["--json", "inspect", str(pdf_encrypted)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["results"][0]["protection"] == "user-password"


def test_inspect_writes_nothing(pdf_encrypted: Path) -> None:
    before = set(pdf_encrypted.parent.iterdir())
    main(["inspect", str(pdf_encrypted)])
    assert set(pdf_encrypted.parent.iterdir()) == before


def test_inspect_reports_unsupported_files_without_failing_the_batch(
    pdf_encrypted: Path, png_stub: Path, capsys
) -> None:
    code = main(["inspect", str(pdf_encrypted), str(png_stub)])
    assert code == ExitCode.UNSUPPORTED_FORMAT
    assert "PNG" in capsys.readouterr().err


# ------------------------------------------------------------------- remove
def test_remove_with_password_file(pdf_encrypted: Path, tmp_path: Path, capsys) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    pwfile.chmod(0o600)
    code = main(["remove", str(pdf_encrypted), "--password-file", str(pwfile)])
    assert code == ExitCode.OK
    assert (pdf_encrypted.parent / "secret-unprotected.pdf").exists()
    assert "VERIFIED" in capsys.readouterr().out


def test_remove_json_output(pdf_encrypted: Path, tmp_path: Path, capsys) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    main(["--json", "remove", str(pdf_encrypted), "--password-file", str(pwfile)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["verification"]["encrypted"] == "false"
    assert payload["protection_removed"] == "user-password"


def test_wrong_password_exit_code(pdf_encrypted: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(WRONG_PASSWORD)
    assert main(["remove", str(pdf_encrypted), "--password-file", str(pwfile)]) == 3


def test_unsupported_format_exit_code(rar_stub: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    assert main(["remove", str(rar_stub), "--password-file", str(pwfile)]) == 4


def test_not_protected_exit_code(pdf_plain: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    assert main(["remove", str(pdf_plain), "--password-file", str(pwfile)]) == 6


def test_policy_refusal_exit_code(pdf_restricted: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(OWNER_PASSWORD)
    assert main(["remove", str(pdf_restricted), "--password-file", str(pwfile)]) == 10


def test_output_exists_exit_code(pdf_encrypted: Path, tmp_path: Path) -> None:
    (pdf_encrypted.parent / "secret-unprotected.pdf").write_bytes(b"x")
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    assert main(["remove", str(pdf_encrypted), "--password-file", str(pwfile)]) == 7


def test_batch_partial_failure_exit_code(tmp_path: Path) -> None:
    from fpr.testing import fixtures as F

    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "ok.pdf").write_bytes(
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    )
    (folder / "other.pdf").write_bytes(F.make_pdf(F.PdfSpec(user="different", owner="different2")))
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    assert main(["remove", str(folder), "--password-file", str(pwfile)]) == 12


def test_output_and_multiple_inputs_is_a_usage_error(tmp_path: Path, pdf_encrypted: Path) -> None:
    other = pdf_encrypted.parent / "two.pdf"
    other.write_bytes(pdf_encrypted.read_bytes())
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    code = main(
        ["remove", str(pdf_encrypted), str(other), "-o", "x.pdf", "--password-file", str(pwfile)]
    )
    assert code == ExitCode.USAGE


# --------------------------------------------------------- password plumbing
def test_password_on_argv_is_refused_with_a_reason(pdf_encrypted: Path) -> None:
    result = run(["remove", str(pdf_encrypted), "--password", SAMPLE_PASSWORD])
    assert result.returncode == ExitCode.USAGE
    assert "not accepted on the command line" in result.stderr
    assert "--password-fd" in result.stderr


def test_password_from_stdin(pdf_encrypted: Path) -> None:
    result = run(["remove", str(pdf_encrypted), "--password-stdin"], stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK
    assert (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


def test_two_password_sources_is_a_usage_error(pdf_encrypted: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    result = run(
        ["remove", str(pdf_encrypted), "--password-file", str(pwfile), "--password-stdin"],
        stdin=SAMPLE_PASSWORD,
    )
    assert result.returncode == ExitCode.USAGE
    assert "Choose one password source" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_group_readable_password_file_warns(pdf_encrypted: Path, tmp_path: Path) -> None:
    pwfile = tmp_path / "pw.txt"
    pwfile.write_text(SAMPLE_PASSWORD)
    pwfile.chmod(0o644)
    result = run(["remove", str(pdf_encrypted), "--password-file", str(pwfile)])
    assert result.returncode == ExitCode.OK
    assert "readable by other users" in result.stderr


def test_password_env_warns_loudly(pdf_encrypted: Path) -> None:
    env = dict(os.environ, FPR_TEST_PW=SAMPLE_PASSWORD)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fpr.cli.main",
            "remove",
            str(pdf_encrypted),
            "--password-env",
            "FPR_TEST_PW",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=CHILD_TIMEOUT,
    )
    assert result.returncode == ExitCode.OK
    assert "visible to other processes" in result.stderr


def test_no_password_and_no_tty_is_a_usage_error(pdf_encrypted: Path) -> None:
    result = run(["remove", str(pdf_encrypted)])
    assert result.returncode == ExitCode.USAGE
    assert "not an interactive terminal" in result.stderr


# ------------------------------------------------------------ informational
def test_formats_lists_exclusions_and_policy(capsys) -> None:
    assert main(["formats"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "RAR" in out
    assert "R3" in out


def test_formats_json(capsys) -> None:
    main(["--json", "formats"])
    payload = json.loads(capsys.readouterr().out)
    assert {row["id"] for row in payload["supported"]} >= {"pdf", "ooxml", "zip"}
    assert len(payload["policy"]) == 5


def test_version_reports_dependency_provenance(capsys) -> None:
    assert main(["version"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "pikepdf" in out
    assert "libqpdf" in out


def test_no_command_prints_help(capsys) -> None:
    assert main([]) == ExitCode.USAGE
    assert "usage: fpr" in capsys.readouterr().out
