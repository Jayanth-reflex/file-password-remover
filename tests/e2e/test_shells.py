"""The same journey, in every shell people run this from.

Shells disagree about more than syntax: how a pipe terminates a line, what
encoding `>` writes a file in, whether a numbered descriptor can be handed to
a child, how an exit code is read back. Each script under ``shells/`` is
written in its own shell's idioms and checks every step's exit code itself;
this module supplies the fixtures and runs whichever shells exist here.

Locally a missing shell is a skip. In CI, ``FPR_E2E_SHELLS`` names the shells
that must be present on that runner, so a runner image that quietly drops one
fails the build instead of shrinking the matrix.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fpr.testing import fixtures as F

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD

pytestmark = pytest.mark.e2e

HERE = Path(__file__).parent / "shells"
WINDOWS = sys.platform.startswith("win")
ODD_NAME = "报告 résumé.pdf"  # 报告 résumé.pdf
TIMEOUT = 600


def _usable(shell: str) -> str | None:
    """The first copy of ``shell`` on PATH that this process can actually use.

    On Windows, System32\\bash.exe is the WSL launcher rather than a shell, and
    it can sit ahead of Git Bash on PATH -- so every PATH entry is checked
    instead of trusting the first hit.
    """
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        found = shutil.which(shell, path=directory)
        if found and not (WINDOWS and "system32" in found.lower()):
            return found
    return None


def _posix(shell: str) -> list[str] | None:
    found = _usable(shell)
    return None if found is None else [found, str(HERE / "journey.sh")]


def _powershell(executable: str) -> list[str] | None:
    found = _usable(executable)
    if found is None:
        return None
    return [
        found,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(HERE / "journey.ps1"),
    ]


def _cmd() -> list[str] | None:
    if not WINDOWS:
        return None
    return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(HERE / "journey.cmd")]


SHELLS = {
    "sh": lambda: _posix("sh"),
    "dash": lambda: _posix("dash"),
    "bash": lambda: _posix("bash"),
    "zsh": lambda: _posix("zsh"),
    "pwsh": lambda: _powershell("pwsh"),
    "powershell": lambda: _powershell("powershell") if WINDOWS else None,
    "cmd": _cmd,
}


def _required() -> set[str]:
    return {s for s in os.environ.get("FPR_E2E_SHELLS", "").split(",") if s}


def _fixtures(work: Path) -> None:
    locked = F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    for name in ("locked.pdf", "with spaces.pdf", ODD_NAME):
        (work / name).write_bytes(locked)
    (work / "plain.pdf").write_bytes(F.make_pdf())
    (work / "archive.zip").write_bytes(F.make_zip_aes())
    pw = work / "pw.txt"
    pw.write_bytes(SAMPLE_PASSWORD.encode() + b"\n")
    if not WINDOWS:
        pw.chmod(0o600)


def test_every_required_shell_is_present() -> None:
    missing = sorted(name for name in _required() if SHELLS.get(name, lambda: None)() is None)
    assert not missing, f"required shells missing on this runner: {missing}"


@pytest.mark.parametrize("shell", sorted(SHELLS))
def test_the_journey_in_this_shell(shell: str, fpr_bin: Path, tmp_path: Path) -> None:
    command = SHELLS[shell]()
    if command is None:
        if shell in _required():
            pytest.fail(f"{shell} is required on this runner but was not found")
        pytest.skip(f"{shell} is not available here")

    work = tmp_path / "work"
    work.mkdir()
    _fixtures(work)

    if shell in {"pwsh", "powershell"}:
        argv = [*command, "-Fpr", str(fpr_bin), "-Work", str(work), "-Odd", ODD_NAME]
    else:
        argv = [*command, str(fpr_bin), str(work), ODD_NAME]

    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        env=env,
        check=False,
    )
    transcript = f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    assert result.returncode == 0, transcript
    assert "JOURNEY OK" in result.stdout, transcript
