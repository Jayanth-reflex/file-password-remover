"""The menu: the first thing most people see, and the only screen that has to
explain the whole tool.

Three things are tested here, because all three have been got wrong by real
programs: that the menu cannot drift out of sync with the commands that
actually exist, that colour is never the only thing carrying a meaning, and
that it degrades to something a `cmd.exe` window or a CI log can print.
"""

from __future__ import annotations

import io

import pytest

from fpr import __version__
from fpr.cli.main import build_parser
from fpr.cli.output import Renderer


class FakeStream(io.StringIO):
    """A StringIO that can pretend to be a terminal with a given encoding."""

    def __init__(self, tty: bool = False, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding

    def isatty(self) -> bool:
        return self._tty


def _render(**kwargs: object) -> str:
    stream = FakeStream(**kwargs)  # type: ignore[arg-type]
    Renderer(stream).menu()
    return stream.getvalue()


def _subcommands() -> set[str]:
    parser = build_parser()
    actions = [a for a in parser._actions if a.dest == "command"]
    assert actions, "the parser no longer has a subcommand group"
    return set(actions[0].choices or {})


def test_the_menu_names_every_command_the_parser_accepts() -> None:
    """A command added without a menu row is a command nobody finds."""
    text = _render()
    missing = {name for name in _subcommands() if name not in text}
    assert not missing, f"commands missing from the menu: {sorted(missing)}"


def test_the_menu_shows_the_version() -> None:
    assert __version__ in _render()


def test_the_menu_says_the_original_is_never_changed() -> None:
    # The single most common fear about a tool like this.
    assert "never" in _render().lower()


def test_every_command_carries_its_effect_in_words_not_only_colour() -> None:
    """Colour is an accent. The words have to survive without it."""
    plain = _render()
    for effect in ("reads only", "unlocks", "locks"):
        assert effect in plain, f"{effect!r} is not stated in words"


def test_colour_is_emitted_on_a_terminal_and_withheld_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FPR_FORCE_COLOR", raising=False)
    assert "\033[" in _render(tty=True)
    assert "\033[" not in _render(tty=False)


def test_no_color_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\033[" not in _render(tty=True)


def test_the_menu_falls_back_to_ascii_on_a_latin1_terminal() -> None:
    text = _render(encoding="latin-1")
    text.encode("latin-1")  # raises if a glyph slipped through


def test_the_menu_fits_a_narrow_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "80")
    for line in _render().splitlines():
        assert len(line) <= 80, f"line overflows 80 columns: {line!r}"


def test_windows_colour_waits_for_virtual_terminal_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows, claiming colour before enabling VT prints escape bytes.

    `cmd.exe` and older PowerShell hosts do not interpret ANSI sequences until
    ``ENABLE_VIRTUAL_TERMINAL_PROCESSING`` is set on the console handle. A tool
    that assumes a TTY means colour paints `←[36m` over its own output there.
    """
    from fpr.cli import output

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FPR_FORCE_COLOR", raising=False)
    stream = FakeStream(tty=True)

    monkeypatch.setattr(output, "enable_ansi", lambda _stream: False)
    assert output.supports_colour(stream) is False

    monkeypatch.setattr(output, "enable_ansi", lambda _stream: True)
    assert output.supports_colour(stream) is True


def test_enable_ansi_is_a_no_op_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    from fpr.cli import output

    monkeypatch.setattr(output, "_is_windows", lambda: False)
    assert output.enable_ansi(FakeStream(tty=True)) is True
