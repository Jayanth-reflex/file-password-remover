"""Shared fixtures.

Every sample file is generated here from :mod:`fpr.testing.fixtures`; nothing
is committed as a binary and nothing is downloaded. That keeps the repository
free of opaque blobs and means a failing test can always be reproduced from
source.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from fpr.testing import fixtures as F

SAMPLE_PASSWORD = F.SAMPLE_PASSWORD
WRONG_PASSWORD = F.WRONG_PASSWORD
OWNER_PASSWORD = F.OWNER_PASSWORD


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, bytes], Path]:
    """Write bytes into the test's temp directory and return the path."""

    def _write(name: str, data: bytes) -> Path:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    return _write


# --------------------------------------------------------------------- PDF
@pytest.fixture
def pdf_plain(write) -> Path:
    return write("plain.pdf", F.make_pdf())


@pytest.fixture
def pdf_encrypted(write) -> Path:
    """AES-256 (R6), user password set, owner password different."""
    return write(
        "secret.pdf",
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD, revision=6)),
    )


@pytest.fixture
def pdf_restricted(write) -> Path:
    """Empty user password, owner password set, printing/extraction denied."""
    return write(
        "restricted.pdf",
        F.make_pdf(F.PdfSpec(owner=OWNER_PASSWORD, deny_print=True, deny_extract=True)),
    )


@pytest.fixture
def pdf_corrupt(write) -> Path:
    """Truncated hard enough that the page tree is gone.

    Note 40% of a PDF is deliberate: qpdf *recovers* from lighter damage and
    silently yields fewer pages, which is why the engine verifies page counts
    rather than trusting a successful open.
    """
    return write("broken.pdf", F.truncate(F.make_pdf(), keep=0.3))


@pytest.fixture
def pdf_encrypted_truncated(write) -> Path:
    return write("half.pdf", F.truncate(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD)), keep=0.3))


# ------------------------------------------------------------------- Office
@pytest.fixture
def docx_plain(write) -> Path:
    return write("plain.docx", F.make_docx())


@pytest.fixture
def docx_encrypted(write) -> Path:
    return write("secret.docx", F.make_encrypted_ooxml(F.make_docx()))


@pytest.fixture
def xlsx_encrypted(write) -> Path:
    return write("secret.xlsx", F.make_encrypted_ooxml(F.make_xlsx()))


@pytest.fixture
def pptx_encrypted(write) -> Path:
    return write("secret.pptx", F.make_encrypted_ooxml(F.make_pptx()))


@pytest.fixture
def docx_restricted(write) -> Path:
    return write("readonly.docx", F.make_docx_restricted())


# --------------------------------------------------------------------- ZIP
@pytest.fixture
def zip_plain(write) -> Path:
    return write("plain.zip", F.make_zip_plain())


@pytest.fixture
def zip_aes(write) -> Path:
    return write("aes.zip", F.make_zip_aes())


@pytest.fixture
def zip_zipcrypto(write) -> Path:
    return write("legacy.zip", F.make_zip_zipcrypto())


@pytest.fixture
def zip_mixed(write) -> Path:
    return write("mixed.zip", F.make_zip_mixed())


# ---------------------------------------------------------------------- 7z
@pytest.fixture
def sevenzip(write) -> Path:
    return write("secret.7z", F.make_sevenzip())


@pytest.fixture
def sevenzip_header(write) -> Path:
    return write("hidden.7z", F.make_sevenzip(encrypt_header=True))


# ------------------------------------------------------------ legacy Office
@pytest.fixture
def legacy_doc_encrypted(write) -> Path:
    return write("legacy.doc", F.make_legacy_doc(encrypted=True))


@pytest.fixture
def legacy_doc_plain(write) -> Path:
    return write("legacy-plain.doc", F.make_legacy_doc(encrypted=False))


# ------------------------------------------------------------------- other
@pytest.fixture
def png_stub(write) -> Path:
    return write("image.png", F.NOT_AN_ARCHIVE)


@pytest.fixture
def rar_stub(write) -> Path:
    return write("archive.rar", F.RAR_STUB)


def pytest_collection_modifyitems(config, items):
    """Skip the optional-extra tests when py7zr is not installed."""
    try:
        import py7zr  # noqa: F401

        have_7z = True
    except ImportError:
        have_7z = False
    if have_7z:
        return
    skip = pytest.mark.skip(reason="optional extra 'sevenzip' (py7zr) is not installed")
    for item in items:
        if "sevenzip" in item.keywords:
            item.add_marker(skip)


# ------------------------------------------------------------------ desktop
@pytest.fixture(scope="session")
def tk_root():
    """One Tk root for the whole session.

    Creating and destroying several Tk roots inside one process hangs on macOS,
    so the window is built once and its contents are rebuilt per test. Shared
    here because both the integration tests and the end-to-end journeys drive
    the window, and they run in the same process.
    """
    tk = pytest.importorskip("tkinter")
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
