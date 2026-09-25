"""One version number, declared in eleven places, checked in one test.

Every platform this ships on wants the version in its own file format: a
``pyproject.toml`` key, a Gradle DSL assignment, an Xcode build setting, a
Swift constant, a JSON-LD blob in the marketing page. Nothing but this test
connects them, so without it a release ships an iPhone build that reports the
previous version and nobody notices until a bug report arrives with the wrong
number attached.

``fpr.__version__`` is the source of truth. Everything else is checked against
it, and the failure message names the file so the fix is mechanical.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fpr import __version__

ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _one(pattern: str, text: str, where: str) -> str:
    found = re.findall(pattern, text)
    assert found, f"no version declaration matching {pattern!r} in {where}"
    assert len(set(found)) == 1, f"{where} declares several versions: {sorted(set(found))}"
    return str(found[0])


# Each entry is (file, regex with one capture group). A new platform gets a row
# here on the day it gains a version, not on the day it drifts.
DECLARATIONS = [
    ("pyproject.toml", r'(?m)^version = "([^"]+)"'),
    ("android/app/build.gradle.kts", r'versionName = "([^"]+)"'),
    ("android/fprkit/src/main/kotlin/dev/jayanth/fpr/Version.kt", r'VERSION = "([^"]+)"'),
    ("ios/FprKit/Sources/FprKit/Version.swift", r'version = "([^"]+)"'),
    ("scripts/gen_xcodeproj.py", r'MARKETING_VERSION = "([^"]+)"'),
    ("ios/FilePasswordRemover.xcodeproj/project.pbxproj", r"MARKETING_VERSION = ([0-9][^;]*);"),
    ("site/index.html", r'"softwareVersion": "([^"]+)"'),
]


@pytest.mark.parametrize(("relative", "pattern"), DECLARATIONS)
def test_declared_version_matches_the_package(relative: str, pattern: str) -> None:
    assert _one(pattern, _read(relative), relative) == __version__


def test_the_marketing_page_shows_the_shipping_version() -> None:
    # The badge in the hero is the number a visitor actually reads.
    assert f"v{__version__}" in _read("site/index.html")


def test_the_changelog_has_an_entry_for_this_version() -> None:
    assert f"## [{__version__}]" in _read("CHANGELOG.md")
    assert f"[{__version__}]: https" in _read("CHANGELOG.md"), "the link reference is missing"


def test_the_android_version_code_advances_with_the_version() -> None:
    """Play refuses an upload whose versionCode has not increased."""
    gradle = _read("android/app/build.gradle.kts")
    code = int(_one(r"versionCode = (\d+)", gradle, "build.gradle.kts"))
    major, minor, patch = (int(part) for part in __version__.split("."))
    assert code == major * 10000 + minor * 100 + patch
