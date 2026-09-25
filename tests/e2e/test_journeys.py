"""Whole journeys through the installed executable.

Every other suite tests one thing at a time. These tests do what a person does:
several commands in a row, each one consuming what the last one produced. That
is where the interesting failures live -- a password that prints but cannot be
typed back in, a JSON field an agent needs that was never emitted, an output
name the next command cannot find.

Written against the shipped behaviour rather than ahead of it: the commands
already existed, and this suite exists to stop them drifting apart from each
other.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fpr import __version__
from fpr.errors import ExitCode
from fpr.testing import fixtures as F

from ..conftest import SAMPLE_PASSWORD

pytestmark = pytest.mark.e2e


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def plain_pdf(tmp_path: Path) -> Path:
    target = tmp_path / "notes.pdf"
    target.write_bytes(F.make_pdf())
    return target


@pytest.fixture
def locked_zip(tmp_path: Path) -> Path:
    target = tmp_path / "archive.zip"
    target.write_bytes(F.make_zip_aes(password=SAMPLE_PASSWORD))
    return target


# ------------------------------------------------------------ the front door
def test_a_bare_fpr_shows_the_menu(fpr) -> None:
    result = fpr()
    assert result.returncode == ExitCode.USAGE
    for command in ("inspect", "remove", "protect", "formats", "version"):
        assert command in result.stdout
    # The promise that matters most, on the first screen.
    assert "never changed" in result.stdout


def test_every_surface_reports_the_same_version(fpr, as_json) -> None:
    assert fpr("--version").stdout.strip() == f"fpr {__version__}"
    assert as_json(fpr("--json", "version"))["fpr"] == __version__


def test_the_menu_is_printed_without_escape_sequences_when_piped(fpr) -> None:
    """capture_output means no TTY, which is also what a CI log and `| less` are."""
    assert "\033[" not in fpr().stdout


# --------------------------------------------------- lock it, then unlock it
def test_a_generated_password_locks_a_file_and_then_opens_it_again(
    fpr, plain_pdf: Path, tmp_path: Path
) -> None:
    """The whole point of `--generate`, across three commands.

    If the password that is written out cannot be fed back in, the file is
    gone -- and this tool refuses, by design, to crack it back open. Nothing
    short of a full round trip proves that cannot happen.
    """
    before = _digest(plain_pdf)
    pw_file = tmp_path / "pw.txt"

    locked = fpr("protect", "notes.pdf", "--generate", "--password-out", str(pw_file))
    assert locked.returncode == ExitCode.OK, locked.stderr
    protected = tmp_path / "notes-protected.pdf"
    assert protected.exists()
    assert pw_file.read_text().strip()

    seen = fpr("--json", "inspect", "notes-protected.pdf")
    assert seen.returncode == ExitCode.OK
    import json

    (found,) = json.loads(seen.stdout)["results"]
    assert found["protection"] != "none"

    opened = fpr(
        "remove", "notes-protected.pdf", "--password-file", str(pw_file), "-o", "reopened.pdf"
    )
    assert opened.returncode == ExitCode.OK, opened.stderr
    assert (tmp_path / "reopened.pdf").exists()

    assert _digest(plain_pdf) == before, "the original was modified"


def test_an_agent_can_round_trip_a_file_using_only_json(fpr, as_json, tmp_path: Path) -> None:
    """The machine contract, end to end.

    An agent that calls `protect --generate --json` and cannot read the password
    back out of the response has destroyed the file it was asked to secure.
    """
    (tmp_path / "data.zip").write_bytes(F.make_zip_aes(password=SAMPLE_PASSWORD))
    unlocked = fpr("--json", "remove", "data.zip", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert unlocked.returncode == ExitCode.OK, unlocked.stderr
    plain = Path(as_json(unlocked)["output"])

    locked = fpr("--json", "protect", plain.name, "--generate")
    payload = as_json(locked)
    assert locked.returncode == ExitCode.OK, locked.stderr
    password = payload["generated_password"]
    assert password

    reopened = fpr(
        "--json",
        "remove",
        Path(payload["output"]).name,
        "--password-stdin",
        "-o",
        "final.zip",
        stdin=password,
    )
    assert reopened.returncode == ExitCode.OK, reopened.stderr
    assert (tmp_path / "final.zip").exists()


def test_a_supplied_password_is_never_echoed_back(fpr, tmp_path: Path) -> None:
    (tmp_path / "book.pdf").write_bytes(F.make_pdf())
    result = fpr("protect", "book.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr
    assert SAMPLE_PASSWORD not in result.stdout
    assert SAMPLE_PASSWORD not in result.stderr


# ------------------------------------------------------------------ refusals
def test_a_wrong_password_writes_nothing_and_exits_three(
    fpr, locked_zip: Path, tmp_path: Path
) -> None:
    result = fpr(
        "remove",
        "archive.zip",
        "--password-stdin",
        "-o",
        "should-not-exist.zip",
        stdin="definitely-not-it",
    )
    assert result.returncode == ExitCode.WRONG_PASSWORD
    assert not (tmp_path / "should-not-exist.zip").exists()


def test_protecting_an_already_protected_file_is_refused(fpr, locked_zip: Path) -> None:
    result = fpr("protect", "archive.zip", "--generate")
    assert result.returncode != ExitCode.OK
    assert "already protected" in (result.stderr + result.stdout).lower()


def test_generating_a_password_for_a_batch_is_refused(fpr, tmp_path: Path) -> None:
    """One generated password shown once, for several files, loses most of them."""
    for name in ("one.pdf", "two.pdf"):
        (tmp_path / name).write_bytes(F.make_pdf())
    result = fpr("protect", "one.pdf", "two.pdf", "--generate")
    assert result.returncode == ExitCode.USAGE


# --------------------------------------------------------------------- batch
def test_a_folder_of_mixed_files_reports_per_item(fpr, as_json, tmp_path: Path) -> None:
    folder = tmp_path / "inbox"
    folder.mkdir()
    (folder / "a.zip").write_bytes(F.make_zip_aes(password=SAMPLE_PASSWORD))
    (folder / "b.zip").write_bytes(F.make_zip_aes(password=SAMPLE_PASSWORD))
    (folder / "notes.txt").write_text("not a supported format")

    result = fpr(
        "--json",
        "remove",
        "inbox",
        "--recursive",
        "--pattern",
        "*.zip",
        "--output-dir",
        "clean",
        "--password-stdin",
        stdin=SAMPLE_PASSWORD,
    )
    payload = as_json(result)
    assert payload["removed"] == 2
    assert sorted(p.name for p in (tmp_path / "clean").iterdir()) == [
        "a-unprotected.zip",
        "b-unprotected.zip",
    ]


def test_formats_states_which_direction_each_format_works_in(fpr, as_json) -> None:
    payload = as_json(fpr("--json", "formats"))
    by_id = {row["id"]: row for row in payload["supported"]}
    assert by_id["pdf"]["can_protect"] == "yes"
    # Claiming protection for a format that cannot do it is how someone ends up
    # with an unencrypted copy they believe is safe.
    assert by_id["ooxml"]["can_protect"] == "no"
