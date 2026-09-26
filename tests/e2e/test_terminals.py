"""The executable in a real terminal, not a pipe.

Every other test captures output through a pipe, which is exactly the case
where colour is off, the password prompt is refused, and the console's own
behaviour never comes into it. What a person sees is different: a terminal
that is a TTY, a prompt that must not echo what is typed, and -- on Windows --
a console that prints escape sequences literally unless the tool asks it not to.

On macOS and Linux, a pseudo-terminal stands in for the terminal window. On
Windows, the test opens a real console with ``CREATE_NEW_CONSOLE`` and reads
back what was drawn into its screen buffer.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fpr.errors import ExitCode
from fpr.testing import fixtures as F

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD

pytestmark = pytest.mark.e2e

WINDOWS = sys.platform.startswith("win")
posix_only = pytest.mark.skipif(WINDOWS, reason="pseudo-terminals are POSIX")
windows_only = pytest.mark.skipif(not WINDOWS, reason="the Windows console is Windows-only")

DEADLINE = 120.0


# ------------------------------------------------------ POSIX pseudo-terminal
# Run in the child: become a session leader, adopt the pty as the controlling
# terminal (which is what getpass opens), then exec the tool. Doing this in a
# spawned helper rather than with pty.fork() keeps a Python-level fork out of
# pytest's multi-threaded process.
_ADOPT_TTY = """
import fcntl, os, sys, termios
os.setsid()
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
except OSError:
    pass  # Linux already adopted it on open
for target in (0, 1, 2):
    os.dup2(fd, target)
if fd > 2:
    os.close(fd)
os.execv(sys.argv[2], sys.argv[2:])
"""


class Terminal:
    """One child process whose controlling terminal is a pseudo-terminal.

    The parent keeps its own copy of the slave open until the child has exited.
    Without it there is a window, before the child opens the slave, in which no
    process holds it and a read on the master fails with EIO -- which looks
    exactly like the child having already finished.
    """

    def __init__(self, argv: list[str], cwd: Path, env: dict[str, str]) -> None:
        master, slave = os.openpty()
        self.process = subprocess.Popen(
            [sys.executable, "-c", _ADOPT_TTY, os.ttyname(slave), *argv],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.fd, self.slave = master, slave
        self.transcript = b""

    def _pump(self, timeout: float) -> None:
        import select

        ready, _, _ = select.select([self.fd], [], [], timeout)
        if ready:
            # EIO marks the end of the stream on some platforms.
            with contextlib.suppress(OSError):
                self.transcript += os.read(self.fd, 4096)

    def expect(self, needle: bytes) -> None:
        start = time.monotonic()
        while needle not in self.transcript and time.monotonic() - start < DEADLINE:
            self._pump(0.2)
            if self.process.poll() is not None:
                self._pump(0.2)
                break
        assert needle in self.transcript, f"never saw {needle!r}; got {self.transcript!r}"

    def send(self, text: str) -> None:
        os.write(self.fd, text.encode())

    def wait(self) -> int:
        # Keep reading while waiting. A pty buffers about a kilobyte, so a child
        # printing a full report blocks on write until somebody drains it --
        # waiting without reading deadlocks on the first long result.
        start = time.monotonic()
        while self.process.poll() is None:
            if time.monotonic() - start > DEADLINE:
                self.process.kill()
                raise AssertionError(f"the child did not exit; transcript {self.transcript!r}")
            self._pump(0.1)
        code = self.process.returncode
        # Drain what the child wrote before it exited.
        before = -1
        while before != len(self.transcript):
            before = len(self.transcript)
            self._pump(0.1)
        os.close(self.slave)
        os.close(self.fd)
        return code


@pytest.fixture
def terminal(fpr_bin: Path, tmp_path: Path):
    def _open(*args: str, extra_env: dict[str, str] | None = None) -> Terminal:
        env = {k: v for k, v in os.environ.items() if k not in {"NO_COLOR", "FPR_FORCE_COLOR"}}
        env["TERM"] = "xterm-256color"
        env.update(extra_env or {})
        return Terminal([str(fpr_bin), *args], tmp_path, env)

    return _open


@posix_only
def test_a_terminal_gets_colour_without_being_asked(terminal) -> None:
    session = terminal()
    assert session.wait() == ExitCode.USAGE
    assert b"\033[" in session.transcript
    # The brass accent, which needs a 256-colour terminal.
    assert b"38;5;179" in session.transcript


@posix_only
def test_no_color_is_honoured_in_a_terminal(terminal) -> None:
    session = terminal(extra_env={"NO_COLOR": "1"})
    assert session.wait() == ExitCode.USAGE
    assert b"\033[" not in session.transcript


@posix_only
def test_an_eight_colour_terminal_gets_the_plain_accent(terminal) -> None:
    session = terminal(extra_env={"TERM": "xterm", "COLORTERM": ""})
    session.wait()
    assert b"38;5;179" not in session.transcript
    assert b"\033[33m" in session.transcript


@posix_only
def test_the_prompt_reads_a_password_and_never_echoes_it(terminal, tmp_path: Path) -> None:
    (tmp_path / "locked.pdf").write_bytes(
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    )
    session = terminal("remove", "locked.pdf")
    session.expect(b"Password:")
    session.send(SAMPLE_PASSWORD + "\r")
    assert session.wait() == ExitCode.OK, session.transcript
    assert (tmp_path / "locked-unprotected.pdf").exists()
    assert SAMPLE_PASSWORD.encode() not in session.transcript, "the password was echoed"
    # A real terminal gets the glyphs, not the ASCII fallback.
    assert "✓".encode() in session.transcript


@posix_only
def test_protect_confirms_and_a_mismatch_writes_nothing(terminal, tmp_path: Path) -> None:
    (tmp_path / "notes.pdf").write_bytes(F.make_pdf())
    session = terminal("protect", "notes.pdf")
    session.expect(b"Password:")
    session.send("first attempt\r")
    session.expect(b"Confirm password:")
    session.send("second attempt\r")
    assert session.wait() != ExitCode.OK
    assert not (tmp_path / "notes-protected.pdf").exists()


@posix_only
def test_protect_with_a_confirmed_password_reopens_with_it(terminal, tmp_path: Path, fpr) -> None:
    (tmp_path / "notes.pdf").write_bytes(F.make_pdf())
    session = terminal("protect", "notes.pdf")
    session.expect(b"Password:")
    session.send("typed by a person\r")
    session.expect(b"Confirm password:")
    session.send("typed by a person\r")
    assert session.wait() == ExitCode.OK, session.transcript
    assert b"typed by a person" not in session.transcript

    reopened = fpr(
        "remove",
        "notes-protected.pdf",
        "--password-stdin",
        "-o",
        "x.pdf",
        stdin="typed by a person",
    )
    assert reopened.returncode == ExitCode.OK


@posix_only
def test_ctrl_c_at_the_prompt_writes_nothing(terminal, tmp_path: Path) -> None:
    (tmp_path / "locked.pdf").write_bytes(
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    )
    session = terminal("remove", "locked.pdf")
    session.expect(b"Password:")
    session.send("\x03")
    assert session.wait() != ExitCode.OK
    assert not (tmp_path / "locked-unprotected.pdf").exists()


# ----------------------------------------------------- the Windows console
_CONSOLE_PROBE = r"""
import ctypes, json, subprocess, sys
from ctypes import wintypes

out_path, fpr = sys.argv[1], sys.argv[2]
kernel32 = ctypes.windll.kernel32

# Run the tool attached to this console, exactly as cmd.exe would.
code = subprocess.call([fpr])

# Read back what the console actually drew.
handle = kernel32.GetStdHandle(-11)

class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

class SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

class INFO(ctypes.Structure):
    _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD), ("wAttributes", wintypes.WORD),
                ("srWindow", SMALL_RECT), ("dwMaximumWindowSize", COORD)]

info = INFO()
kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info))
width, rows = info.dwSize.X, info.dwCursorPosition.Y + 1
buffer = ctypes.create_unicode_buffer(width * rows)
read = wintypes.DWORD()
kernel32.ReadConsoleOutputCharacterW(handle, buffer, width * rows, COORD(0, 0), ctypes.byref(read))
text = buffer.value[: read.value]

attributes = (wintypes.WORD * (width * rows))()
kernel32.ReadConsoleOutputAttribute(handle, attributes, width * rows, COORD(0, 0), ctypes.byref(read))

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump({"code": code, "text": text, "attributes": sorted(set(attributes[: read.value]))}, fh)
"""


@windows_only
def test_the_windows_console_interprets_colour_instead_of_printing_it(
    fpr_bin: Path, tmp_path: Path
) -> None:  # pragma: no cover - Windows only
    """What cmd.exe shows, read back out of the console's screen buffer.

    Without virtual terminal processing, the buffer contains the literal
    characters ``[33mFPR`` -- the escape byte itself is not drawn, but the rest
    of the sequence is. With it, the buffer contains ``FPR`` and the colour lives
    in the cell attributes instead.
    """
    import json

    probe = tmp_path / "probe.py"
    probe.write_text(_CONSOLE_PROBE, encoding="utf-8")
    result_file = tmp_path / "console.json"
    env = {k: v for k, v in os.environ.items() if k not in {"NO_COLOR", "FPR_FORCE_COLOR"}}
    subprocess.run(
        [sys.executable, str(probe), str(result_file), str(fpr_bin)],
        creationflags=subprocess.CREATE_NEW_CONSOLE,  # type: ignore[attr-defined]
        env=env,
        timeout=DEADLINE,
        check=True,
    )
    drawn = json.loads(result_file.read_text(encoding="utf-8"))

    assert drawn["code"] == ExitCode.USAGE
    assert "FPR" in drawn["text"] and "inspect" in drawn["text"]
    assert "[33m" not in drawn["text"] and "[0m" not in drawn["text"], (
        "the console printed escape sequences instead of interpreting them"
    )
    # More than one foreground colour was used: the menu really is in colour.
    assert len(drawn["attributes"]) > 1
