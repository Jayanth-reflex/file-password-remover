"""7-Zip archives (optional extra)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fpr import Secret, inspect, remove

from ..conftest import SAMPLE_PASSWORD, WRONG_PASSWORD

pytestmark = pytest.mark.sevenzip


def _contents(path: Path, tmp_path: Path) -> dict[str, bytes]:
    """Expand an archive into a scratch dir and return its file contents."""
    import py7zr

    target = tmp_path / f"extract-{path.stem}"
    target.mkdir(parents=True, exist_ok=True)
    with py7zr.SevenZipFile(path, "r") as archive:
        archive.extractall(path=str(target))
    return {
        member.relative_to(target).as_posix(): member.read_bytes()
        for member in sorted(target.rglob("*"))
        if member.is_file()
    }


def _expected() -> dict[str, bytes]:
    from fpr.testing import fixtures as F

    return dict(F._ZIP_MEMBERS)  # noqa: SLF001


def test_detects_aes(sevenzip: Path) -> None:
    d = inspect(sevenzip)
    assert d.algorithm == "AES-256"


def test_detects_encrypted_header(sevenzip_header: Path) -> None:
    d = inspect(sevenzip_header)
    assert "header" in d.detail or "header" in (d.algorithm or "")


def test_round_trips(sevenzip: Path, tmp_path: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(sevenzip, pw)
    assert _contents(result.output, tmp_path) == _expected()
    assert result.verification["encrypted"] == "false"


def test_encrypted_header_round_trips(sevenzip_header: Path, tmp_path: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(sevenzip_header, pw)
    assert _contents(result.output, tmp_path) == _expected()


def test_wrong_password_is_rejected(sevenzip: Path) -> None:
    from fpr.errors import IncorrectPasswordError

    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(sevenzip, pw)


def test_licence_warning_is_surfaced(sevenzip: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(sevenzip, pw)
    assert any("LGPL" in w for w in result.warnings)


def test_a_wrong_password_that_stalls_the_decoder_fails_fast(tmp_path: Path) -> None:
    """The archive that hung CI for five minutes, reproduced on purpose.

    With this IV, WRONG_PASSWORD decrypts to bytes the LZMA decoder accepts
    until the packed input is exhausted, and py7zr then loops forever waiting
    for output that cannot come. Run in a child process with a deadline, so a
    regression fails this test instead of hanging the suite.
    """
    import subprocess
    import sys

    from fpr.errors import ExitCode
    from fpr.testing import fixtures as F

    archive = tmp_path / "stalls.7z"
    archive.write_bytes(F.make_sevenzip(iv=F.SEVENZIP_STALLING_IV))
    try:
        result = subprocess.run(
            [sys.executable, "-m", "fpr.cli.main", "remove", str(archive), "--password-stdin"],
            input=WRONG_PASSWORD,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("a wrong password made 7-Zip extraction hang")
    assert result.returncode == ExitCode.WRONG_PASSWORD, result.stderr
    assert not list(tmp_path.glob("*-unprotected*"))


def test_the_stalling_archive_still_opens_with_the_right_password(tmp_path: Path) -> None:
    """The guard must not mistake a real archive for a stalled one."""
    from fpr.testing import fixtures as F

    archive = tmp_path / "stalls.7z"
    archive.write_bytes(F.make_sevenzip(iv=F.SEVENZIP_STALLING_IV))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(archive, pw)
    assert _contents(result.output, tmp_path) == _expected()


def test_the_no_progress_guard_is_installed() -> None:
    """A py7zr upgrade that moves the decompressor silently disables the guard.

    The regression test above would then hang for its full deadline; this says
    why, at once. See docs/adr/0012-guard-py7zr-against-no-progress.md.
    """
    import py7zr.compressor

    import fpr.adapters.sevenzip  # noqa: F401 -- installs the guard

    decompress = py7zr.compressor.SevenZipDecompressor.decompress
    assert getattr(decompress, "_fpr_guarded", False), "py7zr's decompressor is not guarded"


def test_a_wrong_password_that_ends_the_stream_early_is_a_wrong_password(tmp_path: Path) -> None:
    """Not an I/O error: nothing is wrong with the disk, only with the key."""
    from fpr.errors import IncorrectPasswordError
    from fpr.testing import fixtures as F

    archive = tmp_path / "early-eof.7z"
    archive.write_bytes(F.make_sevenzip(iv=F.SEVENZIP_EARLY_EOF_IV))
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(archive, pw)
    assert not list(tmp_path.glob("*-unprotected*"))
