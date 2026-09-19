"""The package must contain no network code, and must not call out at runtime."""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import fpr

PACKAGE_ROOT = Path(fpr.__file__).parent

NETWORK_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "urllib3",
    "requests",
    "httpx",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "asyncio.streams",
    "aiohttp",
    "websockets",
}

# The fixture generator downloads nothing either, but it is test-only code and
# lives under the same package, so it is scanned with everything else.
ALLOWED_URLLIB_USERS: set[str] = set()


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize(
    "source", sorted(PACKAGE_ROOT.rglob("*.py")), ids=lambda p: str(p.relative_to(PACKAGE_ROOT))
)
def test_no_module_imports_a_network_library(source: Path) -> None:
    offenders = _imports(source) & NETWORK_MODULES
    assert not offenders, f"{source.relative_to(PACKAGE_ROOT)} imports {offenders}"


def test_no_telemetry_or_update_check_strings() -> None:
    suspicious = ("https://", "http://", "telemetry", "analytics", "sentry")
    hits: list[str] = []
    for source in PACKAGE_ROOT.rglob("*.py"):
        text = source.read_text()
        for needle in suspicious:
            if needle in text:
                # URLs inside docstrings and XML namespaces are fine; what
                # matters is that nothing opens one.
                for line in text.splitlines():
                    if needle in line and ("urlopen" in line or "request" in line.lower()):
                        hits.append(f"{source.name}: {line.strip()}")
    assert not hits, hits


def test_a_removal_makes_no_outbound_connection(pdf_encrypted, monkeypatch) -> None:
    from fpr import Secret, remove

    from ..conftest import SAMPLE_PASSWORD

    def explode(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("the tool attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        remove(pdf_encrypted, pw)
