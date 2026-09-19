"""ZIP archives: AES, ZipCrypto, mixed, and the safety limits."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from fpr import Secret, remove
from fpr.errors import IncorrectPasswordError, UnsupportedFormatError

from ..conftest import SAMPLE_PASSWORD, WRONG_PASSWORD


def _contents(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as zf:
        return {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}


def _expected() -> dict[str, bytes]:
    from fpr.testing import fixtures as F

    return dict(F._ZIP_MEMBERS)  # noqa: SLF001 - the fixture's own member list


@pytest.mark.parametrize("fixture", ["zip_aes", "zip_zipcrypto"])
def test_contents_round_trip(fixture: str, request: pytest.FixtureRequest) -> None:
    path = request.getfixturevalue(fixture)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert _contents(result.output) == _expected()
    assert result.verification["encrypted"] == "false"


def test_output_has_no_encrypted_entries(zip_aes: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_aes, pw)
    with zipfile.ZipFile(result.output) as zf:
        assert all(not (i.flag_bits & 0x1) for i in zf.infolist())
        assert all(i.compress_type != 99 for i in zf.infolist())


def test_aes_extra_field_is_stripped(zip_aes: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_aes, pw)
    with zipfile.ZipFile(result.output) as zf:
        assert all(b"\x01\x99" not in (i.extra or b"") for i in zf.infolist())


def test_metadata_is_preserved(zip_aes: Path) -> None:
    with zipfile.ZipFile(zip_aes) as zf:
        before = {i.filename: i.date_time for i in zf.infolist()}
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_aes, pw)
    with zipfile.ZipFile(result.output) as zf:
        assert {i.filename: i.date_time for i in zf.infolist()} == before


def test_archive_comment_is_preserved(zip_zipcrypto: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_zipcrypto, pw)
    with zipfile.ZipFile(result.output) as zf:
        assert zf.comment == b"fpr fixture"


def test_mixed_archive_keeps_the_unencrypted_entries(zip_mixed: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_mixed, pw)
    out = _contents(result.output)
    assert out["public.txt"] == b"not secret\n" * 10
    assert out["private.txt"] == b"secret\n" * 10


def test_wrong_aes_password_is_rejected(zip_aes: Path) -> None:
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(zip_aes, pw)


def test_wrong_zipcrypto_password_is_rejected(zip_zipcrypto: Path) -> None:
    with Secret.from_text(WRONG_PASSWORD) as pw, pytest.raises(IncorrectPasswordError):
        remove(zip_zipcrypto, pw)


def test_plain_zip_reports_nothing_to_do(zip_plain: Path) -> None:
    from fpr.errors import NotProtectedError

    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(NotProtectedError):
        remove(zip_plain, pw)


@pytest.mark.parametrize("bits", [128, 192, 256])
def test_every_aes_strength(write, bits: int) -> None:
    from fpr.testing import fixtures as F

    path = write(f"aes{bits}.zip", F.make_zip_aes(bits=bits))
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    assert f"AES-{bits}" in (result.algorithm or "")
    assert _contents(result.output) == _expected()


def test_zipcrypto_run_warns_about_the_cipher(zip_zipcrypto: Path) -> None:
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(zip_zipcrypto, pw)
    assert any("ZipCrypto" in w for w in result.warnings)


def test_decompression_bomb_is_refused(write, monkeypatch) -> None:
    from fpr.adapters import zipfiles
    from fpr.testing.zipcrypto import ZipEntry, build_zipcrypto_archive

    monkeypatch.setattr(zipfiles, "MAX_TOTAL_UNCOMPRESSED", 4096)
    blob = build_zipcrypto_archive([ZipEntry("bomb.bin", b"\x00" * 200_000)], SAMPLE_PASSWORD)
    path = write("bomb.zip", blob)
    with Secret.from_text(SAMPLE_PASSWORD) as pw, pytest.raises(UnsupportedFormatError) as exc:
        remove(path, pw)
    assert "safety limit" in exc.value.message
    assert not (path.parent / "bomb-unprotected.zip").exists()


def test_directory_entries_survive(write) -> None:
    import pyzipper

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
        zf.writestr("emptydir/", b"")
        zf.setpassword(SAMPLE_PASSWORD.encode())
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr("emptydir/file.txt", b"content")
    path = write("dirs.zip", buf.getvalue())
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    with zipfile.ZipFile(result.output) as zf:
        assert "emptydir/" in zf.namelist()
        assert zf.read("emptydir/file.txt") == b"content"
