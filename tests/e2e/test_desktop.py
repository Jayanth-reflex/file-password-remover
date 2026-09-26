"""Whole journeys through the desktop window.

The integration tests check one control at a time. These follow a person:
lock a file in the window, then load what was written back into the same
window and open it with the password the window showed. Every format the app
offers is driven through it, on whichever desktop this runs on -- macOS,
Windows, or Linux under xvfb in CI.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from fpr.testing import fixtures as F

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD, WRONG_PASSWORD
from ..gui_support import settle

pytestmark = [pytest.mark.e2e, pytest.mark.gui]


def _members(data: bytes, password: str | None = None) -> dict[str, bytes]:
    import pyzipper

    with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
        if password:
            archive.setpassword(password.encode())
        return {i.filename: archive.read(i.filename) for i in archive.infolist()}


def _open(app, path: Path, password: str) -> None:
    app.load(path)
    settle(app)
    assert app.available == "remove", f"{path.name} was not offered for opening"
    app.password_var.set(password)
    app.on_run()
    settle(app)


# ----------------------------------------------------- lock, then unlock it
@pytest.mark.parametrize(
    ("name", "make"),
    [
        pytest.param("notes.pdf", F.make_pdf, id="pdf"),
        pytest.param("bundle.zip", F.make_zip_plain, id="zip"),
    ],
)
def test_lock_in_the_window_then_open_it_in_the_window(
    app, tmp_path: Path, name: str, make
) -> None:
    source = tmp_path / name
    source.write_bytes(make())
    original = source.read_bytes()

    app.load(source)
    settle(app)
    assert app.available == "protect"
    app.generate_var.set(True)
    app.on_run()
    settle(app)
    password = app.generated_label.cget("text")
    stem, suffix = name.rsplit(".", 1)
    protected = tmp_path / f"{stem}-protected.{suffix}"
    assert protected.exists()

    _open(app, protected, password)
    assert "Verified" in app.status.cget("text")
    reopened = tmp_path / f"{stem}-protected-unprotected.{suffix}"
    assert reopened.exists()
    if suffix == "zip":
        assert _members(reopened.read_bytes()) == _members(original)
    assert source.read_bytes() == original, "the original was modified"


@pytest.mark.parametrize(
    ("name", "make"),
    [
        pytest.param("letter.docx", lambda: F.make_encrypted_ooxml(F.make_docx()), id="docx"),
        pytest.param("ledger.xlsx", lambda: F.make_encrypted_ooxml(F.make_xlsx()), id="xlsx"),
        pytest.param("aes.zip", F.make_zip_aes, id="zip-aes"),
        pytest.param("legacy.zip", F.make_zip_zipcrypto, id="zip-zipcrypto"),
        pytest.param(
            "r4.pdf",
            lambda: F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD, revision=4)),
            id="pdf-aes-128",
        ),
    ],
)
def test_every_removable_format_opens_in_the_window(app, tmp_path: Path, name: str, make) -> None:
    source = tmp_path / name
    source.write_bytes(make())
    _open(app, source, SAMPLE_PASSWORD)
    assert "Verified" in app.status.cget("text"), app.status.cget("text")
    stem, suffix = name.rsplit(".", 1)
    assert (tmp_path / f"{stem}-unprotected.{suffix}").exists()


def test_a_wrong_password_then_the_right_one(app, tmp_path: Path) -> None:
    """People mistype. The second attempt must not be poisoned by the first."""
    source = tmp_path / "locked.pdf"
    source.write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))

    app.load(source)
    settle(app)
    app.password_var.set(WRONG_PASSWORD)
    import tkinter.messagebox

    shown: list[str] = []
    original = tkinter.messagebox.showerror
    tkinter.messagebox.showerror = lambda *a, **_k: shown.append(str(a))  # type: ignore[assignment]
    try:
        app.on_run()
        settle(app)
    finally:
        tkinter.messagebox.showerror = original
    assert not (tmp_path / "locked-unprotected.pdf").exists()

    app.password_var.set(SAMPLE_PASSWORD)
    app.on_run()
    settle(app)
    assert (tmp_path / "locked-unprotected.pdf").exists()


def test_restrictions_are_cleared_through_the_checkbox(app, tmp_path: Path) -> None:
    source = tmp_path / "restricted.pdf"
    source.write_bytes(
        F.make_pdf(F.PdfSpec(owner=OWNER_PASSWORD, deny_print=True, deny_extract=True))
    )
    app.load(source)
    settle(app)
    app.restrictions_var.set(True)
    app.password_var.set(OWNER_PASSWORD)
    app.on_run()
    settle(app)

    import pikepdf

    with pikepdf.open(tmp_path / "restricted-unprotected.pdf") as pdf:
        assert pdf.allow.extract and pdf.allow.print_highres


@pytest.mark.parametrize("name", ["with spaces.pdf", "报告 résumé.pdf", "😀.pdf"])
def test_awkward_names_in_the_window(app, tmp_path: Path, name: str) -> None:
    source = tmp_path / name
    source.write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))
    _open(app, source, SAMPLE_PASSWORD)
    stem = name.rsplit(".", 1)[0]
    assert (tmp_path / f"{stem}-unprotected.pdf").exists()


# --------------------------------------------- a password the user chose
def test_a_chosen_password_must_be_typed_twice(app, tmp_path: Path) -> None:
    """A mistyped character behind a mask locks the file for good.

    This tool refuses to crack passwords, so a file protected with a password
    the user did not mean to type cannot be opened again by anyone. The CLI asks
    twice for this reason; the window has to as well.
    """
    source = tmp_path / "notes.pdf"
    source.write_bytes(F.make_pdf())
    app.load(source)
    settle(app)
    app.generate_var.set(False)
    app.password_var.set("typed carefully")
    app.confirm_var.set("typed carefuly")

    import tkinter.messagebox

    shown: list[str] = []
    original = tkinter.messagebox.showinfo
    tkinter.messagebox.showinfo = lambda *a, **_k: shown.append(" ".join(map(str, a)))  # type: ignore[assignment]
    try:
        app.on_run()
        settle(app)
    finally:
        tkinter.messagebox.showinfo = original

    assert not (tmp_path / "notes-protected.pdf").exists(), "protected with a mismatched password"
    assert any("match" in message.lower() for message in shown)


def test_a_chosen_password_typed_twice_protects_and_reopens(app, tmp_path: Path) -> None:
    source = tmp_path / "notes.pdf"
    source.write_bytes(F.make_pdf())
    app.load(source)
    settle(app)
    app.generate_var.set(False)
    app.password_var.set("typed carefully")
    app.confirm_var.set("typed carefully")
    app.on_run()
    settle(app)
    assert (tmp_path / "notes-protected.pdf").exists()
    # Neither field keeps the password once the run has started.
    assert app.password_var.get() == "" and app.confirm_var.get() == ""

    _open(app, tmp_path / "notes-protected.pdf", "typed carefully")
    assert (tmp_path / "notes-protected-unprotected.pdf").exists()


def test_the_confirmation_field_is_only_offered_when_it_means_something(
    app, tmp_path: Path
) -> None:
    """Shown for a password the user chooses; hidden when opening or generating."""
    plain = tmp_path / "plain.pdf"
    plain.write_bytes(F.make_pdf())
    locked = tmp_path / "locked.pdf"
    locked.write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))

    app.root.deiconify()
    try:
        app.load(plain)
        settle(app)
        app.generate_var.set(False)
        app._sync_password_mode()
        app.root.update()
        assert app.confirm_entry.winfo_ismapped()

        app.generate_var.set(True)
        app._sync_password_mode()
        app.root.update()
        assert not app.confirm_entry.winfo_ismapped()

        app.load(locked)
        settle(app)
        app.root.update()
        assert not app.confirm_entry.winfo_ismapped()
    finally:
        app.root.withdraw()
