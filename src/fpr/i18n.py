"""Message catalogues.

The presentation layers (CLI help text that is not argparse's own, and the
desktop app) look their strings up through :func:`t` so that translating the
product is a matter of adding a JSON file, with no build step and no gettext
toolchain to install. Contributors edit ``fpr/locales/<code>.json``.

Honest scope: **the interface is localisation-ready, and English is the only
catalogue that ships.** Engine and adapter messages -- the detailed
explanations of protection types -- are still English-only strings defined at
their source; moving those behind :func:`t` is tracked in
docs/product/localization.md rather than pretended away here.
"""

from __future__ import annotations

import json
import locale
import os
from functools import cache
from pathlib import Path

__all__ = ["t", "set_language", "current_language", "available_languages", "LOCALE_DIR"]

LOCALE_DIR = Path(__file__).parent / "locales"
_FALLBACK = "en"
_active = _FALLBACK


@cache
def _catalogue(code: str) -> dict[str, str]:
    path = LOCALE_DIR / f"{code}.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def available_languages() -> list[str]:
    return sorted(p.stem for p in LOCALE_DIR.glob("*.json"))


def _detect() -> str:
    for env in ("FPR_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(env)
        if value:
            code = value.split(".")[0].split("_")[0].lower()
            if code and code != "c":
                return code
    # locale.getdefaultlocale() would be the obvious call, but it is deprecated
    # and due for removal in Python 3.15. getlocale() reads the process locale
    # without the deprecation and without mutating global state the way
    # setlocale() would -- which a library has no business doing.
    try:
        system = locale.getlocale()[0]
    except (ValueError, TypeError):  # pragma: no cover - malformed locale env
        return _FALLBACK
    code = system.split("_")[0].lower() if system else _FALLBACK
    # "C" and "POSIX" are the absence of a locale, not a language.
    return _FALLBACK if code in ("c", "posix", "") else code


def set_language(code: str | None = None) -> str:
    """Select a catalogue. ``None`` means "work it out from the environment"."""
    global _active
    _active = (code or _detect() or _FALLBACK).lower()
    return _active


def current_language() -> str:
    return _active


def t(key: str, default: str, **params: object) -> str:
    """Translate ``key``, falling back to ``default`` (the English source text).

    ``default`` is mandatory so that a missing catalogue entry degrades to
    readable English instead of showing the user a dotted key.
    """
    template = _catalogue(_active).get(key) or _catalogue(_FALLBACK).get(key) or default
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError, ValueError):
        # A bad translation must never crash the UI; show the English source.
        return default.format(**params)


set_language()
