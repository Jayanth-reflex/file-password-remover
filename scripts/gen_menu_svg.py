#!/usr/bin/env python3
"""Render the menu to an SVG, from the menu's own output.

A screenshot of a terminal goes stale the moment a row changes, and nobody
notices because an image cannot be linted. This captures the bytes the tool
actually prints -- escape sequences and all -- and translates them, so the
picture in the documentation is generated from the same code path a user sees
and cannot drift away from it.

Run it after changing the menu:

    python scripts/gen_menu_svg.py
"""

from __future__ import annotations

import io
import os
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fpr.cli.output import Renderer  # noqa: E402

OUT = ROOT / "docs" / "assets" / "cli-menu.svg"

# The terminal this picture is of: the design system's graphite, and the
# 256-colour values the renderer emits mapped back to their hex.
BACKGROUND = "#121417"
FOREGROUND = "#E8E6E1"
ANSI_HEX = {
    "0": FOREGROUND,
    "2": "#7C8087",  # dim
    "32": "#6FBF87",  # unlocks
    "33": "#C6A664",  # brass: locks
    "36": "#63B7C4",  # reads only
    "38;5;179": "#C6A664",
}

CELL_WIDTH = 8.4
LINE_HEIGHT = 21
PADDING = 22

_SGR = re.compile(r"\033\[([0-9;]*)m")


class _Terminal(io.StringIO):
    """A stream the renderer will treat as a 96-column colour terminal."""

    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def _spans(line: str) -> list[tuple[str, str]]:
    """Split one line into (text, colour) runs."""
    runs: list[tuple[str, str]] = []
    colour = FOREGROUND
    position = 0
    for match in _SGR.finditer(line):
        text = line[position : match.start()]
        if text:
            runs.append((text, colour))
        code = match.group(1) or "0"
        colour = ANSI_HEX.get(code, FOREGROUND)
        position = match.end()
    tail = line[position:]
    if tail:
        runs.append((tail, colour))
    return runs


def render() -> str:
    # Force colour rather than relying on the stream looking like a terminal.
    # On Windows, colour is claimed only after the console accepts virtual
    # terminal processing, which a StringIO can never do -- without this, the
    # same script would generate a colourless SVG there, and whoever ran
    # `make assets` on Windows would commit it.
    previous = os.environ.get("FPR_FORCE_COLOR")
    os.environ["FPR_FORCE_COLOR"] = "1"
    try:
        stream = _Terminal()
        Renderer(stream).menu()
    finally:
        if previous is None:
            del os.environ["FPR_FORCE_COLOR"]
        else:
            os.environ["FPR_FORCE_COLOR"] = previous
    lines = stream.getvalue().split("\n")
    while lines and not lines[-1].strip():
        lines.pop()

    width = PADDING * 2 + int(
        CELL_WIDTH * max((len(_SGR.sub("", line)) for line in lines), default=0)
    )
    height = PADDING * 2 + LINE_HEIGHT * len(lines)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="The fpr menu, listing inspect, remove, protect, formats and version, '
        f'each with what it does to your files">',
        f'<rect width="{width}" height="{height}" rx="10" fill="{BACKGROUND}"/>',
        '<g font-family="SFMono-Regular,Menlo,Consolas,monospace" font-size="14">',
    ]
    for index, line in enumerate(lines):
        baseline = PADDING + LINE_HEIGHT * index + 14
        column = 0
        for text, colour in _spans(line):
            x = PADDING + CELL_WIDTH * column
            parts.append(
                f'<text x="{x:.1f}" y="{baseline}" fill="{colour}" '
                f'xml:space="preserve">{escape(text)}</text>'
            )
            column += len(text)
    parts.append("</g></svg>")
    return "\n".join(parts) + "\n"


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
