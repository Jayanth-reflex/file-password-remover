"""Getting the password into the process without leaking it.

Ranked by how much exposure each route carries:

``--password-fd N``   Best for automation. The parent writes to a pipe; the
                      value never touches argv, the environment or the disk.
``--password-file P``  Fine when the file is 0600 on a local disk. The tool
                      warns when the file is group/world readable.
``--password-stdin``   Equivalent to ``--password-fd 0``; convenient in shells.
interactive prompt     The default. Uses ``getpass``, so the terminal echo is
                      off and the value never reaches the shell history.
``--password-env VAR`` Discouraged and warned about: the environment of a
                      process is readable by the same user's other processes on
                      several platforms, and leaks into crash reports.

There is deliberately **no** ``--password VALUE``. Command lines are visible to
every process on the machine via ``ps``, and they land in shell history. The
option is still parsed, purely so that the tool can say exactly that instead of
failing with "unrecognised argument".
"""

from __future__ import annotations

import argparse
import getpass
import os
import stat
import sys
from pathlib import Path

from ..errors import UsageError
from ..secret import Secret, SecretError

__all__ = ["resolve_secret", "add_password_arguments", "PasswordSource", "stdin_is_interactive"]


class PasswordSource:
    FD = "fd"
    FILE = "file"
    STDIN = "stdin"
    ENV = "env"
    PROMPT = "prompt"


def add_password_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the password options to an ``argparse`` parser or group."""
    group = parser.add_argument_group(
        "password input",
        "Pick exactly one. Without any of these, you are prompted on the terminal.",
    )
    group.add_argument(
        "--password-fd",
        type=int,
        metavar="N",
        help="Read the password from an already-open file descriptor (recommended for scripts).",
    )
    group.add_argument(
        "--password-file",
        type=Path,
        metavar="PATH",
        help="Read the password from a file. One trailing newline is stripped.",
    )
    group.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from standard input.",
    )
    group.add_argument(
        "--password-env",
        metavar="VAR",
        help="Read the password from an environment variable (discouraged; warns).",
    )
    # Present only to produce a good error message. See the module docstring.
    group.add_argument("--password", metavar="VALUE", help=argparse.SUPPRESS)


def resolve_secret(
    args: argparse.Namespace, *, prompt: str = "Password: ", confirm: bool = False
) -> Secret:
    """Build a :class:`~fpr.secret.Secret` from whichever option was given."""
    if getattr(args, "password", None) is not None:
        raise UsageError(
            "Passwords are not accepted on the command line: every process on this machine "
            "can read another process's arguments, and your shell records them in its history.",
            remediation=(
                "Use --password-fd, --password-file, --password-stdin, or just let the tool "
                "prompt you."
            ),
        )

    chosen = [
        name
        for name, present in (
            (PasswordSource.FD, getattr(args, "password_fd", None) is not None),
            (PasswordSource.FILE, getattr(args, "password_file", None) is not None),
            (PasswordSource.STDIN, bool(getattr(args, "password_stdin", False))),
            (PasswordSource.ENV, getattr(args, "password_env", None) is not None),
        )
        if present
    ]
    if len(chosen) > 1:
        raise UsageError(
            f"Choose one password source; {len(chosen)} were given ({', '.join(chosen)})."
        )

    try:
        if not chosen:
            return _from_prompt(prompt, confirm=confirm)
        source = chosen[0]
        if source == PasswordSource.FD:
            return Secret.from_fd(int(args.password_fd))
        if source == PasswordSource.FILE:
            path = Path(args.password_file)
            _warn_if_readable(path)
            return Secret.from_file(path)
        if source == PasswordSource.STDIN:
            return Secret.from_fd(sys.stdin.fileno())
        name = str(args.password_env)
        value = os.environ.get(name)
        if value is None:
            raise UsageError(f"Environment variable {name} is not set.")
        print(
            f"warning: reading the password from ${name}. Environment variables are visible to "
            "other processes you run and are captured by crash reporters.",
            file=sys.stderr,
        )
        return Secret.from_text(value)
    except SecretError as exc:
        raise UsageError(str(exc)) from exc


def stdin_is_interactive() -> bool:
    """Whether a human can actually be prompted on this process's stdin.

    ``isatty()`` alone is not enough on Windows. There it is true for any
    *character device*, and ``NUL`` -- what a service, a scheduled task or a
    ``< NUL`` redirect supplies -- is a character device. The prompt would then
    be considered safe to show, and ``getpass`` on Windows reads the console
    directly rather than stdin, so it blocks forever on input that cannot
    arrive. ``GetConsoleMode`` succeeds only for a real console handle, which
    is the distinction that matters.
    """
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return False
    except (AttributeError, ValueError):  # detached or closed stdin
        return False

    if os.name != "nt":
        return True

    try:  # pragma: no cover - exercised on Windows only
        import ctypes
        import msvcrt

        # mypy runs on the Linux CI host, where these Windows-only
        # attributes do not exist on the stubs.
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())  # type: ignore[attr-defined]
        mode = ctypes.c_uint()
        return bool(
            ctypes.windll.kernel32.GetConsoleMode(  # type: ignore[attr-defined]
                ctypes.c_void_p(handle), ctypes.byref(mode)
            )
        )
    except (AttributeError, ImportError, OSError, ValueError):
        # No console handle we can confirm, so refuse to prompt. Failing
        # closed here costs a clear usage error; failing open costs a hang.
        return False


def _from_prompt(prompt: str, *, confirm: bool) -> Secret:
    if not stdin_is_interactive():
        raise UsageError(
            "No password was supplied and this is not an interactive terminal.",
            remediation="Use --password-fd, --password-file or --password-stdin.",
        )
    try:
        first = getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise UsageError("Cancelled.") from exc
    if confirm:
        second = getpass.getpass("Confirm password: ")
        if first != second:
            raise UsageError("The two passwords did not match.")
    if not first:
        raise UsageError("The password was empty.")
    return Secret.from_text(first)


def _warn_if_readable(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        print(
            f"warning: {path} is readable by other users (mode {stat.filemode(mode)}). "
            f"Consider `chmod 600 {path}`.",
            file=sys.stderr,
        )
