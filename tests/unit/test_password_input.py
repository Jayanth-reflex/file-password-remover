"""Password routing: which source wins, and what is refused."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import pytest

from fpr.cli.password_input import add_password_arguments, resolve_secret
from fpr.errors import UsageError


def _args(**overrides: object) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_password_arguments(parser)
    namespace = parser.parse_args([])
    for key, value in overrides.items():
        setattr(namespace, key, value)
    return namespace


def test_argv_password_is_refused_with_an_alternative(tmp_path: Path) -> None:
    with pytest.raises(UsageError) as exc:
        resolve_secret(_args(password="hunter2"))
    assert "command line" in exc.value.message
    assert "--password-fd" in (exc.value.remediation or "")


def test_file_source(tmp_path: Path) -> None:
    path = tmp_path / "pw"
    path.write_text("from-a-file\n")
    with resolve_secret(_args(password_file=path)) as secret, secret.expose() as value:
        assert value == "from-a-file"


def test_fd_source() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"from-a-pipe")
    os.close(write_fd)
    try:
        with resolve_secret(_args(password_fd=read_fd)) as secret, secret.expose() as value:
            assert value == "from-a-pipe"
    finally:
        os.close(read_fd)


def test_env_source(monkeypatch, capsys) -> None:
    monkeypatch.setenv("FPR_TEST_SECRET", "from-the-env")
    with resolve_secret(_args(password_env="FPR_TEST_SECRET")) as secret, secret.expose() as value:
        assert value == "from-the-env"
    assert "visible to other processes" in capsys.readouterr().err


def test_missing_env_variable_is_a_usage_error(monkeypatch) -> None:
    monkeypatch.delenv("FPR_ABSENT", raising=False)
    with pytest.raises(UsageError, match="not set"):
        resolve_secret(_args(password_env="FPR_ABSENT"))


def test_two_sources_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "pw"
    path.write_text("x")
    with pytest.raises(UsageError, match="Choose one password source"):
        resolve_secret(_args(password_file=path, password_stdin=True))


def test_empty_password_file_is_a_usage_error(tmp_path: Path) -> None:
    path = tmp_path / "pw"
    path.write_bytes(b"\n")
    with pytest.raises(UsageError, match="empty"):
        resolve_secret(_args(password_file=path))


def test_prompt_requires_a_terminal(monkeypatch) -> None:
    import sys

    class NotATty:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdin", NotATty())
    with pytest.raises(UsageError, match="interactive terminal"):
        resolve_secret(_args())


def test_prompt_reads_and_confirms(monkeypatch) -> None:
    import sys

    class Tty:
        def isatty(self) -> bool:
            return True

    answers = iter(["typed-in", "typed-in"])
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("fpr.cli.password_input.getpass.getpass", lambda _prompt: next(answers))
    with resolve_secret(_args(), confirm=True) as secret, secret.expose() as value:
        assert value == "typed-in"


def test_prompt_rejects_a_mismatched_confirmation(monkeypatch) -> None:
    import sys

    class Tty:
        def isatty(self) -> bool:
            return True

    answers = iter(["one", "two"])
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("fpr.cli.password_input.getpass.getpass", lambda _prompt: next(answers))
    with pytest.raises(UsageError, match="did not match"):
        resolve_secret(_args(), confirm=True)


def test_prompt_rejects_an_empty_password(monkeypatch) -> None:
    import sys

    class Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("fpr.cli.password_input.getpass.getpass", lambda _prompt: "")
    with pytest.raises(UsageError, match="empty"):
        resolve_secret(_args())


def test_cancelling_the_prompt_is_not_a_crash(monkeypatch) -> None:
    import sys

    class Tty:
        def isatty(self) -> bool:
            return True

    def cancel(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("fpr.cli.password_input.getpass.getpass", cancel)
    with pytest.raises(UsageError, match="Cancelled"):
        resolve_secret(_args())
