"""The password container must not leak, and must wipe."""

from __future__ import annotations

import copy
import os
import pickle
import stat

import pytest

from fpr.secret import MAX_PASSWORD_BYTES, Secret, SecretError


def test_expose_returns_the_password() -> None:
    with Secret.from_text("hunter2") as s, s.expose() as value:
        assert value == "hunter2"


def test_expose_bytes_round_trips_non_ascii() -> None:
    with Secret.from_text("pässwörd-日本語") as s, s.expose_bytes() as raw:
        assert raw.decode("utf-8") == "pässwörd-日本語"


def test_close_wipes_the_buffer_and_blocks_further_access() -> None:
    s = Secret.from_text("hunter2")
    buf = s._buf  # noqa: SLF001 - asserting the wipe is the point of the test
    s.close()
    assert bytes(buf) == b""
    assert s.closed
    with pytest.raises(SecretError), s.expose():
        pass


def test_close_is_idempotent() -> None:
    s = Secret.from_text("x")
    s.close()
    s.close()


def test_repr_str_and_format_never_show_the_password() -> None:
    s = Secret.from_text("topsecret")
    for rendered in (repr(s), str(s), f"{s}", format(s, ">40"), "{}".format(s)):  # noqa: UP032
        assert "topsecret" not in rendered
        assert "Secret" in rendered
    s.close()
    assert "wiped" in repr(s)


def test_cannot_be_pickled_or_copied() -> None:
    s = Secret.from_text("topsecret")
    with pytest.raises((SecretError, TypeError)):
        pickle.dumps(s)
    with pytest.raises(SecretError):
        copy.copy(s)
    with pytest.raises(SecretError):
        copy.deepcopy(s)
    with pytest.raises(SecretError):
        bytes(s)


def test_empty_password_is_rejected() -> None:
    with pytest.raises(SecretError, match="empty"):
        Secret.from_text("")


def test_oversized_password_is_rejected() -> None:
    with pytest.raises(SecretError, match="exceeds"):
        Secret.from_bytes(b"x" * (MAX_PASSWORD_BYTES + 1))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"pw\n", "pw"),
        (b"pw\r\n", "pw"),
        (b"pw", "pw"),
        (b"pw \n", "pw "),  # trailing space is part of the password
        (b"pw\n\n", "pw\n"),  # only ONE newline is stripped
    ],
)
def test_file_input_strips_exactly_one_newline(tmp_path, raw: bytes, expected: str) -> None:
    path = tmp_path / "pw.txt"
    path.write_bytes(raw)
    with Secret.from_file(path) as s, s.expose() as value:
        assert value == expected


def test_fd_input_reads_from_a_pipe() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"from-a-pipe\n")
    os.close(write_fd)
    try:
        with Secret.from_fd(read_fd) as s, s.expose() as value:
            assert value == "from-a-pipe"
    finally:
        os.close(read_fd)


def test_oversized_password_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * (MAX_PASSWORD_BYTES + 10))
    with pytest.raises(SecretError, match="limit"):
        Secret.from_file(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_reading_a_group_readable_file_still_works(tmp_path) -> None:
    # The CLI warns; the library does not refuse, because the user may have
    # deliberately used a shared file.
    path = tmp_path / "pw.txt"
    path.write_bytes(b"shared")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    with Secret.from_file(path) as s, s.expose() as value:
        assert value == "shared"


def test_equality_is_identity_only() -> None:
    a = Secret.from_text("same")
    b = Secret.from_text("same")
    assert a != b
    assert a == a
    a.close()
    b.close()
