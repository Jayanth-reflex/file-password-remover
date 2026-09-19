"""Output placement, atomicity, and the "never touch the original" rule."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from fpr import RemovalOptions, Secret, plan_output_path, remove
from fpr.errors import FileAccessError, OutputExistsError

from ..conftest import SAMPLE_PASSWORD


def test_default_name_sits_beside_the_original(pdf_encrypted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    assert result.output == pdf_encrypted.parent / "secret-unprotected.pdf"
    assert pdf_encrypted.exists()


def test_custom_suffix(pdf_encrypted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw, RemovalOptions(suffix="-open"))
    assert result.output.name == "secret-open.pdf"


def test_explicit_output_path(pdf_encrypted: Path, tmp_path: Path) -> None:
    target = tmp_path / "somewhere" / "clean.pdf"
    target.parent.mkdir()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw, RemovalOptions(output=target))
    assert result.output == target
    assert target.exists()


def test_output_directory(pdf_encrypted: Path, tmp_path: Path) -> None:
    outdir = tmp_path / "clean"
    outdir.mkdir()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw, RemovalOptions(output_dir=outdir))
    assert result.output == outdir / "secret-unprotected.pdf"


def test_existing_output_is_not_clobbered(pdf_encrypted: Path) -> None:
    target = pdf_encrypted.parent / "secret-unprotected.pdf"
    target.write_bytes(b"do not lose me")
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(OutputExistsError) as exc:
        remove(pdf_encrypted, pw)
    assert exc.value.exit_code == 7
    assert target.read_bytes() == b"do not lose me"


def test_overwrite_is_opt_in(pdf_encrypted: Path) -> None:
    target = pdf_encrypted.parent / "secret-unprotected.pdf"
    target.write_bytes(b"stale")
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        remove(pdf_encrypted, pw, RemovalOptions(overwrite=True))
    assert target.read_bytes() != b"stale"


def test_in_place_replaces_the_source_only_when_asked(pdf_encrypted: Path) -> None:
    import pikepdf

    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw, RemovalOptions(in_place=True))
    assert result.output == pdf_encrypted
    with pikepdf.open(pdf_encrypted) as pdf:
        assert not pdf.is_encrypted


def test_output_equal_to_input_without_in_place_is_refused(pdf_encrypted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(FileAccessError) as exc:
        remove(pdf_encrypted, pw, RemovalOptions(output=pdf_encrypted))
    assert "--in-place" in (exc.value.remediation or "")


def test_timestamps_are_preserved_by_default(pdf_encrypted: Path) -> None:
    os.utime(pdf_encrypted, (1_600_000_000, 1_600_000_000))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    assert int(result.output.stat().st_mtime) == 1_600_000_000


def test_timestamp_preservation_can_be_turned_off(pdf_encrypted: Path) -> None:
    os.utime(pdf_encrypted, (1_600_000_000, 1_600_000_000))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw, RemovalOptions(preserve_timestamps=False))
    assert int(result.output.stat().st_mtime) != 1_600_000_000


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_output_is_not_world_readable_even_if_the_source_was(pdf_encrypted: Path) -> None:
    pdf_encrypted.chmod(0o644)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    assert stat.S_IMODE(result.output.stat().st_mode) == 0o600


def test_no_temporary_files_are_left_behind(pdf_encrypted: Path, tmp_path: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        remove(pdf_encrypted, pw)
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".fpr-")] == []


def test_plan_output_path_does_not_create_anything(pdf_encrypted: Path) -> None:
    planned = plan_output_path(pdf_encrypted, RemovalOptions())
    assert not planned.exists()


def test_result_reports_sizes_and_duration(pdf_encrypted: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(pdf_encrypted, pw)
    assert result.bytes_in == pdf_encrypted.stat().st_size
    assert result.bytes_out == result.output.stat().st_size
    assert result.duration_s >= 0
