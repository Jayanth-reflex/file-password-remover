"""Adapter lookup: which handler owns a given file.

Order matters. OOXML packages *are* ZIP files and encrypted OOXML packages are
OLE files, so the more specific adapters are consulted first. Identification is
by content, never by extension: renaming ``secret.docx`` to ``secret.zip`` must
not change what the tool does to it (but it *is* reported, so the user knows).
"""

from __future__ import annotations

from pathlib import Path

from .adapters.base import HEAD_BYTES, Adapter
from .adapters.ooxml import OoxmlAdapter
from .adapters.pdf import PdfAdapter
from .adapters.zipfiles import ZipAdapter
from .errors import FileAccessError, UnsupportedFormatError
from .types import Detection

__all__ = ["ADAPTERS", "adapter_for", "detect", "read_head", "known_formats"]


def _optional_adapters() -> list[type[Adapter]]:
    """Adapters whose dependency is an optional extra."""
    found: list[type[Adapter]] = []
    try:
        from .adapters.sevenzip import SevenZipAdapter
    except ImportError:  # pragma: no cover - exercised by the no-extra CI job
        return found
    found.append(SevenZipAdapter)
    return found


def _all_adapters() -> list[type[Adapter]]:
    from .adapters.legacy_office import LegacyOfficeAdapter

    # Most specific first.
    return [PdfAdapter, OoxmlAdapter, LegacyOfficeAdapter, *_optional_adapters(), ZipAdapter]


ADAPTERS: list[type[Adapter]] = _all_adapters()


def read_head(path: Path) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(HEAD_BYTES)
    except OSError as exc:
        raise FileAccessError(f"Cannot read {path}: {exc.strerror}") from exc


def adapter_for(path: Path) -> Adapter:
    """Return the adapter that owns ``path``.

    Raises :class:`~fpr.errors.UnsupportedFormatError` with a description of
    what *was* recognised, rather than a bare "unsupported".
    """
    head = read_head(path)
    for cls in ADAPTERS:
        if cls.sniff(head, path):
            return cls()
    raise UnsupportedFormatError(
        f"{path.name}: this file type is not supported ({_describe_unknown(head)}).",
        remediation="Run `fpr formats` for the list of supported formats and protections.",
    )


def detect(path: Path) -> Detection:
    """Identify the file and describe its protection, without a password."""
    adapter = adapter_for(path)
    detection = adapter.detect(path)
    expected = {e.lower() for e in adapter.extensions}
    if expected and path.suffix.lower() not in expected:
        return Detection(
            path=detection.path,
            format_id=detection.format_id,
            format_name=detection.format_name,
            protection=detection.protection,
            removability=detection.removability,
            algorithm=detection.algorithm,
            detail=detection.detail,
            extension_mismatch=True,
        )
    return detection


_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (
        b"Rar!\x1a\x07",
        "RAR archive - unsupported: the only complete implementation is "
        "licensed so that it cannot be redistributed with this project",
    ),
    (b"\x1f\x8b", "gzip stream - gzip has no password protection"),
    (b"\xfd7zXZ\x00", "xz stream - xz has no password protection"),
    (b"BZh", "bzip2 stream - bzip2 has no password protection"),
    (b"\x89PNG\r\n\x1a\n", "PNG image - PNG has no password protection"),
    (b"\xff\xd8\xff", "JPEG image - JPEG has no password protection"),
    (b"ITSF", "Windows compiled help (CHM)"),
    (b"KDMv", "KeePass database - use KeePass itself; this is a password store, not a document"),
)


def _describe_unknown(head: bytes) -> str:
    for magic, description in _SIGNATURES:
        if head.startswith(magic):
            return description
    printable = head[:8].hex(" ")
    return f"unrecognised signature {printable}"


def known_formats() -> list[dict[str, str]]:
    """Machine-readable summary for ``fpr formats`` and for the GUI."""
    rows: list[dict[str, str]] = []
    for cls in ADAPTERS:
        rows.append(
            {
                "id": cls.format_id.value,
                "name": cls.format_name,
                "extensions": " ".join(cls.extensions),
            }
        )
    return rows


UNSUPPORTED_BY_DESIGN: tuple[tuple[str, str], ...] = (
    (
        "RAR (.rar)",
        "The reference unrar implementation's licence forbids the redistribution "
        "terms this project needs; no compatible clean-room decoder exists.",
    ),
    (
        "DRM-protected ebooks (.acsm, Kindle, Apple Books)",
        "Removing DRM is a different act from "
        "removing a password you own, and is illegal in many jurisdictions.",
    ),
    (
        "Encrypted disk images (.dmg, VeraCrypt, BitLocker)",
        "These are volumes, not documents; use the operating system's own tooling.",
    ),
    (
        "Office editing restrictions",
        "The content is not encrypted; the 'password' is only a hash "
        "and removal would be a bypass.",
    ),
    (
        "PDF certificate security (Adobe.PubSec)",
        "Needs the private key from a certificate store, not a password.",
    ),
)
