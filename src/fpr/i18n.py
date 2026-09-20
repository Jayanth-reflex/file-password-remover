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


def _looks_like_a_language_code(code: str) -> bool:
    """ISO 639 codes are two or three ASCII letters. Nothing else is one.

    This is the guard that stops a platform-specific locale *name* being used
    as a catalogue name -- see :func:`_system_language`.
    """
    return 2 <= len(code) <= 3 and code.isascii() and code.isalpha()


def _system_language() -> str | None:
    """The operating system's UI language as an ISO 639-1 code, or ``None``."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        # locale.getlocale() returns Windows' own locale names, which are
        # English words: "English_United States", not "en_US". Splitting that
        # on "_" yields "english", which is not a language code and would send
        # the lookup after a catalogue that can never exist. Ask Windows for
        # the UI language and map the LCID through the table the standard
        # library already ships for exactly this.
        try:
            import ctypes

            lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return None
        name = locale.windows_locale.get(lcid)
        return name.split("_")[0].lower() if name else None

    # locale.getdefaultlocale() would be the obvious call, but it is deprecated
    # and due for removal in Python 3.15. getlocale() reads the process locale
    # without the deprecation and without mutating global state the way
    # setlocale() would -- which a library has no business doing.
    try:
        system = locale.getlocale()[0]
    except (ValueError, TypeError):  # pragma: no cover - malformed locale env
        return None
    return system.split("_")[0].lower() if system else None


def _detect() -> str:
    for env in ("FPR_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(env)
        if value:
            code = value.split(".")[0].split("_")[0].lower()
            if code and code != "c":
                return code
    detected = _system_language()
    # "C" and "POSIX" are the absence of a locale, not a language.
    if not detected or detected in ("c", "posix"):
        return _FALLBACK
    return detected if _looks_like_a_language_code(detected) else _FALLBACK


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
