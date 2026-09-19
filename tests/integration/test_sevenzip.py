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
