"""Atomic output, private temp space, and scrubbing."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from fpr.errors import FileAccessError, OutputExistsError
from fpr.securefs import assert_readable_file, atomic_write, scrub_file, secure_tempdir


def test_atomic_write_publishes_only_on_success(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with atomic_write(dest) as tmp:
        tmp.write_bytes(b"payload")
        assert not dest.exists(), "destination must not appear until the block completes"
    assert dest.read_bytes() == b"payload"


def test_atomic_write_leaves_nothing_behind_on_failure(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    with pytest.raises(ValueError, match="boom"), atomic_write(dest) as tmp:
        tmp.write_bytes(b"partial")
        raise ValueError("boom")
    assert not dest.exists()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".fpr-")]
    assert leftovers == []


def test_atomic_write_refuses_to_clobber(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"existing")
    with pytest.raises(OutputExistsError):
        with atomic_write(dest) as tmp:
            tmp.write_bytes(b"new")
    assert dest.read_bytes() == b"existing"


def test_atomic_write_overwrites_when_asked(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    dest.write_bytes(b"existing")
    with atomic_write(dest, overwrite=True) as tmp:
        tmp.write_bytes(b"new")
    assert dest.read_bytes() == b"new"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_temp_file_is_private(tmp_path: Path) -> None:
    seen = {}
    with atomic_write(tmp_path / "out.bin") as tmp:
        seen["mode"] = stat.S_IMODE(tmp.stat().st_mode)
        tmp.write_bytes(b"x")
    assert seen["mode"] == 0o600


def test_temp_file_is_on_the_destination_filesystem(tmp_path: Path) -> None:
    # Same-directory temp keeps os.replace atomic and avoids spreading
    # plaintext across volumes.
    with atomic_write(tmp_path / "out.bin") as tmp:
        assert tmp.parent == tmp_path
        tmp.write_bytes(b"x")


def test_atomic_write_rejects_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="does not exist"):
        with atomic_write(tmp_path / "nope" / "out.bin"):
            pass


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_secure_tempdir_is_private_and_removed() -> None:
    with secure_tempdir() as d:
        assert stat.S_IMODE(d.stat().st_mode) == 0o700
        (d / "leak.txt").write_bytes(b"decrypted bytes")
        recorded = d
    assert not recorded.exists()


def test_secure_tempdir_removes_nested_content() -> None:
    with secure_tempdir() as d:
        (d / "sub").mkdir()
        (d / "sub" / "a.bin").write_bytes(b"x" * 100)
        recorded = d
    assert not recorded.exists()


def test_scrub_file_zeroes_then_unlinks(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"A" * 4096)
    scrub_file(target)
    assert not target.exists()


def test_scrub_file_tolerates_a_missing_file(tmp_path: Path) -> None:
    scrub_file(tmp_path / "gone.bin")  # must not raise


def test_assert_readable_file_rejects_directories(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="directory"):
        assert_readable_file(tmp_path)


def test_assert_readable_file_rejects_missing(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="not found"):
        assert_readable_file(tmp_path / "nope.pdf")


def test_assert_readable_file_rejects_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty.pdf"
    empty.touch()
    with pytest.raises(FileAccessError, match="empty"):
        assert_readable_file(empty)


def test_assert_readable_file_returns_size(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 17)
    assert assert_readable_file(target) == 17
