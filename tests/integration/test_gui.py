"""The desktop window, driven programmatically.

These tests construct the real Tk window and exercise it through its own
methods, so they catch broken wiring, broken threading and controls that a
keyboard cannot reach. They are skipped where no display is available.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")
pytestmark = pytest.mark.gui


@pytest.fixture(scope="session")
def tk_root():
    """One Tk root for the whole session.

    Creating and destroying several Tk roots inside one process hangs on macOS,
    so the window is built once and its contents are rebuilt per test.
    """
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - headless CI
        pytest.skip(f"no display: {exc}")
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def app(tk_root):
    from fpr_gui.app import App

    for child in tk_root.winfo_children():
        child.destroy()
    instance = App(tk_root)
    yield instance
    instance.stop()
    for child in tk_root.winfo_children():
        child.destroy()


def _settle(app, timeout: float = 20.0) -> None:
    """Pump the Tk event loop until the worker thread's result is applied."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.root.update()
        if not app.busy:
            return
        time.sleep(0.02)
    raise AssertionError("the worker never finished")


def _detail(app) -> str:
    return app.detail.get("1.0", "end")


def test_inspecting_a_file_fills_in_the_details(app, pdf_encrypted: Path) -> None:
    app.load(pdf_encrypted)
    _settle(app)
    text = _detail(app)
    assert "PDF" in text
    assert "user-password" in text
    assert "AES-256" in text


def test_planned_output_is_shown_before_anything_is_written(app, pdf_encrypted: Path) -> None:
    app.load(pdf_encrypted)
    _settle(app)
    assert app.output_label.cget("text").endswith("secret-unprotected.pdf")
    assert not (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


def test_a_successful_run_reports_the_verification_evidence(app, pdf_encrypted: Path) -> None:
    from ..conftest import SAMPLE_PASSWORD

    app.load(pdf_encrypted)
    _settle(app)
    app.password_var.set(SAMPLE_PASSWORD)
    app.on_run()
    _settle(app)
    status = app.status.cget("text")
    assert "Verified" in status
    assert "encrypted=false" in status
    assert "original file was not changed" in status
    assert (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


def test_the_password_field_is_cleared_as_soon_as_the_run_starts(app, pdf_encrypted) -> None:
    from ..conftest import SAMPLE_PASSWORD

    app.load(pdf_encrypted)
    _settle(app)
    app.password_var.set(SAMPLE_PASSWORD)
    app.on_run()
    assert app.password_var.get() == ""
    _settle(app)


def test_a_wrong_password_shows_the_error_and_writes_nothing(app, pdf_encrypted, monkeypatch):
    from ..conftest import WRONG_PASSWORD

    shown: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "fpr_gui.app.messagebox.showerror", lambda title, body: shown.append((title, body))
    )
    app.load(pdf_encrypted)
    _settle(app)
    app.password_var.set(WRONG_PASSWORD)
    app.on_run()
    _settle(app)
    assert shown and "Incorrect password" in shown[0][1]
    assert not (pdf_encrypted.parent / "secret-unprotected.pdf").exists()


def test_restriction_checkbox_is_enabled_only_where_it_applies(
    app, pdf_encrypted: Path, pdf_restricted: Path
) -> None:
    app.load(pdf_encrypted)
    _settle(app)
    assert str(app.restrictions_check.cget("state")) == "disabled"

    app.load(pdf_restricted)
    _settle(app)
    assert str(app.restrictions_check.cget("state")) == "normal"


def test_run_is_disabled_for_a_file_with_nothing_to_remove(app, pdf_plain: Path) -> None:
    app.load(pdf_plain)
    _settle(app)
    assert str(app.run_button.cget("state")) == "disabled"


def test_reveal_button_appears_only_after_a_successful_run(app, pdf_encrypted: Path) -> None:
    """Hidden, not merely disabled: aqua renders disabled buttons ambiguously."""
    from ..conftest import SAMPLE_PASSWORD

    assert not app.reveal_button.winfo_ismapped()
    app.load(pdf_encrypted)
    _settle(app)
    app.root.update()
    assert not app.reveal_button.winfo_ismapped()

    app.password_var.set(SAMPLE_PASSWORD)
    app.on_run()
    _settle(app)
    app.root.deiconify()
    app.root.update()
    assert app.reveal_button.winfo_ismapped()
    app.root.withdraw()


def test_password_is_masked_until_the_user_asks(app) -> None:
    assert app.password_entry.cget("show") == "•"
    app.show_var.set(True)
    app._toggle_password()
    assert app.password_entry.cget("show") == ""


# ------------------------------------------------------------ accessibility
def test_every_control_is_reachable_from_the_keyboard(app) -> None:
    """Walk the focus ring and confirm each interactive widget appears.

    The window has to be mapped for this: ttk's ``takefocus`` handler reports
    that a widget declines focus while it is not viewable, so a withdrawn
    window would make every control look unreachable.
    """
    app.root.deiconify()
    app.root.update()
    expected = {
        str(app.choose_button),
        str(app.password_entry),
        str(app.run_button),
    }
    seen: set[str] = set()
    widget = app.choose_button
    for _ in range(60):
        try:
            widget = widget.tk_focusNext()
        except tk.TclError as error:  # pragma: no cover - runner-dependent
            # tk_focusNext is defined in Tk's focus.tcl, auto-loaded through
            # Tcl's auto_path. Some Windows CI runners ship a Python whose Tk
            # is missing that file, and the failure surfaces two ways depending
            # on how far the autoloader gets: it either cannot read focus.tcl,
            # or the proc never gets defined and the call is an "invalid command
            # name". Both mean the same thing -- this Tk cannot walk a focus
            # ring -- and neither is a defect in this application.
            #
            # Matched on those two signatures only, so a genuine focus
            # regression still fails rather than being skipped away.
            message = str(error)
            if "focus.tcl" not in message and "invalid command name" not in message:
                raise
            pytest.skip(f"this Tk build cannot walk the focus ring: {error}")
        if widget is None:  # pragma: no cover - end of ring
            break
        seen.add(str(widget))
        if expected <= seen:
            break
    app.root.withdraw()
    assert expected <= seen, f"unreachable: {expected - seen}"


def test_no_state_is_conveyed_by_colour_alone(app, pdf_restricted: Path) -> None:
    """Warnings and notes are words, not just a red pixel."""
    app.load(pdf_restricted)
    _settle(app)
    assert "Note:" in _detail(app)


def test_window_has_a_usable_minimum_size(app) -> None:
    width, height = app.root.minsize()
    assert width >= 600 and height >= 480
