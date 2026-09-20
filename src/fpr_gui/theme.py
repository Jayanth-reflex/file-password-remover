"""The desktop theme: one palette, applied to ttk.

Design rationale is in docs/design/design-system.md. In short, the interface is
built around the fact that this tool verifies its own output, so the visual
language is hallmarking -- the small punched marks that certify precious metal
-- rather than the padlocks and shields that belong to tools which break into
things.

Two implementation notes worth knowing before changing anything here:

* The ``clam`` theme is used rather than ``aqua``/``vista``. Those two are drawn
  by the platform and ignore almost every colour you set, which makes a
  consistent identity impossible. ``clam`` is fully themeable and renders the
  same on all three desktops. Native *dialogs* (the file picker, message boxes)
  are left alone, because those genuinely should look like the platform.
* Tk has no notion of a disabled-but-readable colour, so every state is set
  explicitly through ``style.map``. Anything left unmapped falls back to a grey
  that fails contrast.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk

__all__ = ["Palette", "DARK", "LIGHT", "apply", "resolve_appearance"]


# mypy resolves `sys.platform` comparisons against whichever platform it is run
# on and then calls every other branch unreachable -- which, with
# warn_unreachable, fails the build on Linux CI for the macOS branch and vice
# versa. Going through a function keeps the check opaque, so all branches stay
# type-checked everywhere.
def _is_macos() -> bool:
    return sys.platform.startswith("darwin")


def _is_windows() -> bool:
    return sys.platform.startswith("win")


@dataclass(frozen=True)
class Palette:
    """Named colours. Values are duplicated from the design system table."""

    ink: str
    surface: str
    line: str
    mist: str
    platinum: str
    brass: str
    patina: str
    oxide: str
    is_dark: bool


DARK = Palette(
    ink="#121417",
    surface="#1A1D21",
    line="#2A2E34",
    mist="#8B9198",
    platinum="#ECEEF0",
    brass="#C6A664",
    patina="#5E9C86",
    oxide="#A8564B",
    is_dark=True,
)

LIGHT = Palette(
    ink="#F7F7F5",
    surface="#FFFFFF",
    line="#E4E4E0",
    mist="#6B6F76",
    platinum="#15171A",
    brass="#9A7B3A",
    patina="#3F7A63",
    oxide="#94433A",
    is_dark=False,
)


def resolve_appearance(root: tk.Misc) -> Palette:
    """Pick the palette that matches the system, without spawning a process.

    ``FPR_APPEARANCE`` overrides everything, which is what the screenshot
    script and anyone who dislikes the choice will use.

    On macOS the system background colour is readable through Tk itself while
    the default theme is still active, so its luminance settles the question.
    Elsewhere Tk exposes nothing reliable, and the app defaults to dark.
    """
    override = os.environ.get("FPR_APPEARANCE", "").strip().lower()
    if override in {"light", "dark"}:
        return LIGHT if override == "light" else DARK

    if _is_macos():
        try:
            red, green, blue = root.winfo_rgb("systemWindowBackgroundColor")
        except tk.TclError:  # pragma: no cover - older Tk without the colour
            return DARK
        # winfo_rgb returns 16-bit channels.
        luminance = (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 65535
        return LIGHT if luminance > 0.5 else DARK

    return DARK


def _families(root: tk.Misc) -> tuple[str, str]:
    """The body face and the mono face for this platform.

    System faces only: they are what the platform hints best, what the
    accessibility settings scale, and they add nothing to the download.
    """
    available = set(tkfont.families(root))

    if _is_macos():
        body_candidates = ["SF Pro Text", "Helvetica Neue", "Helvetica"]
        mono_candidates = ["SF Mono", "Menlo", "Monaco"]
    elif _is_windows():
        body_candidates = ["Segoe UI Variable Text", "Segoe UI", "Tahoma"]
        mono_candidates = ["Cascadia Mono", "Consolas", "Courier New"]
    else:
        body_candidates = ["Inter", "Cantarell", "Ubuntu", "DejaVu Sans"]
        mono_candidates = ["JetBrains Mono", "Ubuntu Mono", "DejaVu Sans Mono"]

    body = next((name for name in body_candidates if name in available), "TkDefaultFont")
    mono = next((name for name in mono_candidates if name in available), "TkFixedFont")
    return body, mono


def apply(root: tk.Tk) -> tuple[Palette, dict[str, tkfont.Font]]:
    """Theme the window. Returns the palette and the named fonts."""
    palette = resolve_appearance(root)
    body_family, mono_family = _families(root)

    fonts = {
        "display": tkfont.Font(family=body_family, size=20, weight="bold"),
        "title": tkfont.Font(family=body_family, size=13, weight="bold"),
        "body": tkfont.Font(family=body_family, size=12),
        # Captions are the hallmark language: small, upper case, wide tracked.
        # Tk cannot letter-space, so the spacing is done by the caller inserting
        # thin spaces between characters -- see _caption() in app.py.
        "caption": tkfont.Font(family=body_family, size=9),
        "mark": tkfont.Font(family=mono_family, size=11),
        "mono": tkfont.Font(family=mono_family, size=11),
    }

    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(background=palette.ink)

    style.configure(".", background=palette.ink, foreground=palette.platinum)

    style.configure("TFrame", background=palette.ink)
    style.configure("Card.TFrame", background=palette.surface)
    # A one-pixel frame is how you draw a hairline in Tk.
    style.configure("Hairline.TFrame", background=palette.line)

    style.configure(
        "TLabel", background=palette.ink, foreground=palette.platinum, font=fonts["body"]
    )
    style.configure("Display.TLabel", font=fonts["display"], foreground=palette.platinum)
    style.configure("Caption.TLabel", font=fonts["caption"], foreground=palette.mist)
    style.configure("Brass.TLabel", font=fonts["caption"], foreground=palette.brass)
    style.configure("Muted.TLabel", foreground=palette.mist)
    style.configure("Mark.TLabel", font=fonts["mark"], foreground=palette.platinum)
    style.configure("Card.TLabel", background=palette.surface)
    style.configure(
        "CardMark.TLabel",
        background=palette.surface,
        font=fonts["mark"],
        foreground=palette.platinum,
    )
    style.configure(
        "CardCaption.TLabel",
        background=palette.surface,
        font=fonts["caption"],
        foreground=palette.mist,
    )
    style.configure(
        "CardBrass.TLabel",
        background=palette.surface,
        font=fonts["caption"],
        foreground=palette.brass,
    )
    style.configure("Patina.TLabel", foreground=palette.patina)
    style.configure("Oxide.TLabel", foreground=palette.oxide)

    # Buttons: quiet by default, brass only on the focus ring.
    style.configure(
        "TButton",
        background=palette.surface,
        foreground=palette.platinum,
        bordercolor=palette.line,
        lightcolor=palette.surface,
        darkcolor=palette.surface,
        focuscolor=palette.brass,
        borderwidth=1,
        padding=(14, 8),
        font=fonts["body"],
    )
    style.map(
        "TButton",
        background=[("pressed", palette.line), ("active", palette.line), ("disabled", palette.ink)],
        foreground=[("disabled", palette.mist)],
        bordercolor=[("focus", palette.brass), ("disabled", palette.line)],
        lightcolor=[("focus", palette.brass)],
        darkcolor=[("focus", palette.brass)],
    )

    style.configure(
        "Primary.TButton",
        background=palette.brass,
        foreground=palette.ink if palette.is_dark else "#FFFFFF",
        bordercolor=palette.brass,
        lightcolor=palette.brass,
        darkcolor=palette.brass,
        font=fonts["title"],
    )
    style.map(
        "Primary.TButton",
        background=[
            ("pressed", palette.line),
            ("active", palette.brass),
            ("disabled", palette.surface),
        ],
        foreground=[("disabled", palette.mist)],
        bordercolor=[("disabled", palette.line)],
    )

    style.configure(
        "TEntry",
        fieldbackground=palette.surface,
        foreground=palette.platinum,
        insertcolor=palette.brass,
        bordercolor=palette.line,
        lightcolor=palette.line,
        darkcolor=palette.line,
        borderwidth=1,
        padding=8,
    )
    style.map(
        "TEntry",
        bordercolor=[("focus", palette.brass)],
        lightcolor=[("focus", palette.brass)],
        darkcolor=[("focus", palette.brass)],
        fieldbackground=[("disabled", palette.ink)],
        foreground=[("disabled", palette.mist)],
    )

    style.configure(
        "TCheckbutton",
        background=palette.ink,
        foreground=palette.platinum,
        indicatorcolor=palette.surface,
        indicatorbackground=palette.surface,
        bordercolor=palette.line,
        focuscolor=palette.brass,
        font=fonts["body"],
        padding=4,
    )
    style.map(
        "TCheckbutton",
        foreground=[("disabled", palette.mist)],
        indicatorcolor=[("selected", palette.brass), ("disabled", palette.ink)],
        bordercolor=[("focus", palette.brass)],
    )

    style.configure(
        "Horizontal.TProgressbar",
        background=palette.brass,
        troughcolor=palette.surface,
        bordercolor=palette.line,
        lightcolor=palette.brass,
        darkcolor=palette.brass,
        borderwidth=0,
        thickness=2,
    )

    return palette, fonts
