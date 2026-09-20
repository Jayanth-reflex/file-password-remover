"""Message catalogues resolve, fall back, and never crash the UI."""

from __future__ import annotations

import json

import pytest

from fpr import i18n


@pytest.fixture(autouse=True)
def _restore_language():
    before = i18n.current_language()
    yield
    i18n.set_language(before)


def test_english_catalogue_ships_and_is_complete_json() -> None:
    assert "en" in i18n.available_languages()
    data = json.loads((i18n.LOCALE_DIR / "en.json").read_text(encoding="utf-8"))
    assert all(isinstance(v, str) for v in data.values())
    assert "gui.title" in data


def test_known_key_is_translated() -> None:
    i18n.set_language("en")
    assert i18n.t("gui.remove", "fallback") == "Remove protection"


def test_unknown_key_falls_back_to_the_english_source() -> None:
    i18n.set_language("en")
    assert i18n.t("no.such.key", "English source") == "English source"


def test_parameters_are_substituted() -> None:
    i18n.set_language("en")
    assert "/tmp/x.pdf" in i18n.t("gui.status.ok", "{path}", path="/tmp/x.pdf")


def test_a_broken_translation_falls_back_instead_of_raising(monkeypatch) -> None:
    monkeypatch.setattr(i18n, "_catalogue", lambda _code: {"k": "{missing_placeholder}"})
    assert i18n.t("k", "safe {n}", n=1) == "safe 1"


def test_unknown_language_falls_back_to_english() -> None:
    i18n.set_language("zz")
    assert i18n.t("gui.remove", "fallback") == "Remove protection"


@pytest.mark.parametrize("value", ["fr_FR.UTF-8", "de", "pt_BR"])
def test_language_is_detected_from_the_environment(monkeypatch, value: str) -> None:
    monkeypatch.setenv("FPR_LANG", value)
    assert i18n.set_language() == value.split(".")[0].split("_")[0].lower()


def test_c_locale_is_not_treated_as_a_language(monkeypatch) -> None:
    for var in ("FPR_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.setenv(var, "C")
    assert i18n.set_language() == "en"


def test_a_windows_locale_name_is_not_used_as_a_language_code(monkeypatch) -> None:
    """Windows reports "English_United States", not "en_US".

    Splitting that the POSIX way yields "english", which is not a language code
    and would send the catalogue lookup after a file that cannot exist.
    """
    for var in ("FPR_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(i18n.locale, "getlocale", lambda: ("English_United States", "1252"))
    monkeypatch.setattr(i18n.os, "name", "posix")
    assert i18n.set_language() == "en"


@pytest.mark.parametrize("code", ["english", "", "e", "en-us", "abcd", "12"])
def test_implausible_language_codes_are_rejected(code: str) -> None:
    assert not i18n._looks_like_a_language_code(code)


@pytest.mark.parametrize("code", ["en", "de", "fra"])
def test_plausible_language_codes_are_accepted(code: str) -> None:
    assert i18n._looks_like_a_language_code(code)
