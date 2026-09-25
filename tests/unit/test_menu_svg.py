"""The picture of the menu in the README is the menu.

An image cannot be linted, so a screenshot of a terminal goes stale silently:
a row changes, the documentation keeps showing the old one, and nobody finds
out. `scripts/gen_menu_svg.py` generates the asset from the renderer's own
output; this test fails when the committed asset and that output disagree.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ASSET = ROOT / "docs" / "assets" / "cli-menu.svg"


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_menu_svg", ROOT / "scripts" / "gen_menu_svg.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_committed_svg_matches_what_the_menu_prints() -> None:
    if not ASSET.exists():  # pragma: no cover - only on a fresh checkout
        pytest.fail(f"{ASSET.relative_to(ROOT)} is missing; run scripts/gen_menu_svg.py")
    assert ASSET.read_text(encoding="utf-8") == _generator().render(), (
        "the menu changed but docs/assets/cli-menu.svg did not; "
        "run `python scripts/gen_menu_svg.py`"
    )


def test_the_svg_carries_a_text_alternative() -> None:
    """The picture is the only copy of the menu in the README."""
    text = ASSET.read_text(encoding="utf-8")
    assert 'role="img"' in text
    assert "aria-label=" in text
