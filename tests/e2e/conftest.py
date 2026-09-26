"""End-to-end fixtures: the real executable, in a directory it has never seen.

The integration tests call ``main()`` in process and ``python -m fpr.cli.main``
in a child. Neither proves the thing a user runs works: the console script is
generated at install time, it resolves the interpreter differently on Windows
than on POSIX, and it is what a `PATH` lookup, a shell alias and a CI step all
reach for. These tests run that binary and nothing else.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

TIMEOUT = 180
"""Seconds. Long enough for a cold start plus an encrypt on a slow hosted
Windows runner, short enough that a hang fails the job instead of stalling it."""


def _console_script() -> Path | None:
    """Find the ``fpr`` installed alongside the interpreter running the tests.

    Deliberately not ``shutil.which``: a different ``fpr`` earlier on `PATH`
    would turn this suite into a test of somebody else's install.
    """
    bindir = Path(sys.executable).parent
    for name in ("fpr.exe", "fpr"):
        candidate = bindir / name
        if candidate.exists():
            return candidate
    found = shutil.which("fpr")
    return Path(found) if found else None


@pytest.fixture(scope="session")
def fpr_bin() -> Path:
    """The installed executable, or a skip that CI is configured to refuse.

    A skip here is legitimate locally -- a checkout that was never installed
    has no console script to test. In CI it would silently retire the whole
    suite, so ``FPR_E2E_REQUIRE=1`` turns the skip into a failure.
    """
    script = _console_script()
    if script is None:
        message = "the fpr console script is not installed; run `pip install -e .`"
        if os.environ.get("FPR_E2E_REQUIRE"):
            pytest.fail(message)
        pytest.skip(message)
    return script


@pytest.fixture
def fpr(fpr_bin: Path, tmp_path: Path) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Run the executable from inside the test's own directory.

    ``cwd`` is the temp directory so a relative path in an argument behaves the
    way it would for a person standing in a folder of their own documents, and
    so nothing the tool writes by default can land in the source tree.
    """

    def _run(
        *args: str,
        stdin: str | None = None,
        env: dict[str, str | None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        # Colour would put escape sequences through every assertion below.
        environment["NO_COLOR"] = "1"
        # A value of None removes the variable, so a test can undo the default.
        for key, value in (env or {}).items():
            if value is None:
                environment.pop(key, None)
            else:
                environment[key] = value
        return subprocess.run(
            [str(fpr_bin), *args],
            cwd=tmp_path,
            input=stdin if stdin is not None else None,
            stdin=subprocess.DEVNULL if stdin is None else None,
            capture_output=True,
            text=True,
            # The child may legitimately write in a narrower encoding than
            # this process reads in -- that is what several of these tests set
            # up on purpose. Decoding must not turn its output into a crash in
            # the harness.
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT,
            env=environment,
            check=False,
        )

    return _run


@pytest.fixture
def as_json() -> Callable[[subprocess.CompletedProcess[str]], dict]:
    """Parse a run's stdout, failing with the actual output when it is not JSON."""

    def _parse(result: subprocess.CompletedProcess[str]) -> dict:
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:  # pragma: no cover - only on a failure
            pytest.fail(f"stdout was not JSON ({exc}):\n{result.stdout}\n{result.stderr}")
        assert isinstance(parsed, dict)
        return parsed

    return _parse
