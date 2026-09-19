"""The fixture CFB writer must produce containers other tools can read."""

from __future__ import annotations

import io

import olefile
import pytest

from fpr.testing import cfb


def test_round_trips_through_olefile() -> None:
    small = b"<xml/>" * 3
    large = bytes(range(256)) * 64  # > 4096 -> full sectors, not the mini stream
    blob = cfb.write(
        [
            cfb.stream("EncryptionInfo", small),
            cfb.stream("EncryptedPackage", large),
            cfb.storage("\x06DataSpaces", [cfb.stream("Version", b"v" * 10)]),
        ]
    )
    assert olefile.isOleFile(io.BytesIO(blob))
    with olefile.OleFileIO(io.BytesIO(blob)) as ole:
        assert ole.openstream("EncryptionInfo").read() == small
        assert ole.openstream("EncryptedPackage").read() == large
        assert ole.openstream("\x06DataSpaces/Version").read() == b"v" * 10


def test_nested_storages_are_navigable() -> None:
    blob = cfb.write(
        [
            cfb.storage(
                "\x06DataSpaces",
                [
                    cfb.storage(
                        "TransformInfo", [cfb.storage("T", [cfb.stream("\x06Primary", b"p")])]
                    )
                ],
            )
        ]
    )
    with olefile.OleFileIO(io.BytesIO(blob)) as ole:
        assert ole.exists("\x06DataSpaces/TransformInfo/T/\x06Primary")
        assert ole.openstream("\x06DataSpaces/TransformInfo/T/\x06Primary").read() == b"p"


@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 4095, 4096, 4097, 20000])
def test_stream_sizes_around_the_mini_stream_cutoff(size: int) -> None:
    payload = bytes((i * 7) % 256 for i in range(size))
    blob = cfb.write([cfb.stream("S", payload), cfb.stream("Other", b"x" * 100)])
    with olefile.OleFileIO(io.BytesIO(blob)) as ole:
        assert ole.openstream("S").read() == payload


def test_long_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="too long"):
        cfb.CfbNode(name="x" * 40, is_storage=False)


def test_oversized_container_is_refused_rather_than_corrupt() -> None:
    with pytest.raises(cfb.CfbTooLargeError, match="FAT sectors"):
        cfb.write([cfb.stream("Big", b"\x00" * (8 << 20))])
