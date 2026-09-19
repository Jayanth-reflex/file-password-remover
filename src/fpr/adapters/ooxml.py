"""OOXML adapter: password-encrypted .docx / .xlsx / .pptx and friends.

What an "encrypted .docx" actually is
------------------------------------
Nothing like a ZIP. When Word encrypts a document it produces an OLE/CFB
compound file holding an ``EncryptionInfo`` stream (key derivation parameters)
and an ``EncryptedPackage`` stream (the real ZIP, AES-encrypted). So the first
two bytes of a password-protected .docx are ``D0 CF``, not ``PK``. Detection
here keys off that, never off the file extension.

Supported
---------
* ECMA-376 **agile** encryption (Office 2010+; AES-128/192/256, CBC, SHA-family).
* ECMA-376 **standard** encryption (Office 2007; AES-128, SHA-1).

Refused
-------
* ``<w:documentProtection>``, ``<workbookProtection>``, ``<sheetProtection>``
  -- "editing restrictions". The package is not encrypted at all; the password
  exists only as a hash, and every tool that "removes" these simply deletes the
  XML element without checking anything. That is a bypass, so this adapter
  reports the restriction and refuses. See docs/product/format-matrix.md.
* Information Rights Management (IRM). The key lives on a rights server.

Memory note
-----------
``msoffcrypto`` decrypts the package into memory in one piece, so peak RSS is
roughly the size of the document. This is an upstream constraint, recorded in
docs/reports/performance.md rather than worked around with a fake stream.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from ..errors import (
    CorruptFileError,
    IncorrectPasswordError,
    PolicyRefusedError,
    UnsupportedFormatError,
    VerificationError,
)
from ..secret import Secret
from ..types import Detection, FormatId, Protection, Removability
from .base import Adapter, AdapterOptions, RemovalEvidence

__all__ = ["OoxmlAdapter", "OLE_MAGIC", "ZIP_MAGIC"]

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"

_CONTENT_TYPES = "[Content_Types].xml"

_RESTRICTION_MARKERS = {
    "word/settings.xml": ("<w:documentProtection", "document editing restrictions"),
    "xl/workbook.xml": ("<workbookProtection", "workbook structure protection"),
    "ppt/presentation.xml": ("<p:modifyVerifier", "presentation modification protection"),
}

_OOXML_SUFFIXES = (
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".xlsb",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
)


def _office_file(path: Path):  # type: ignore[no-untyped-def]
    """Open ``path`` with msoffcrypto, mapping its errors onto ours."""
    import msoffcrypto
    from msoffcrypto import exceptions as mse

    fh = path.open("rb")
    try:
        return msoffcrypto.OfficeFile(fh), fh
    except mse.FileFormatError as exc:
        fh.close()
        raise UnsupportedFormatError(
            f"This is an OLE compound file, but not a recognised Office document: {exc}",
            remediation="Run `fpr inspect` for what was detected.",
        ) from exc
    except Exception:
        fh.close()
        raise


class OoxmlAdapter(Adapter):
    format_id = FormatId.OOXML
    format_name = "Office Open XML (Word/Excel/PowerPoint)"
    extensions = _OOXML_SUFFIXES

    # ------------------------------------------------------------- identity
    @classmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        if head.startswith(OLE_MAGIC):
            # Could be an encrypted OOXML package or a legacy .doc/.xls/.ppt.
            # Ask msoffcrypto which; the legacy adapter claims the rest.
            return _ole_is_ooxml(path)
        if head.startswith(ZIP_MAGIC):
            return _zip_is_ooxml(path)
        return False

    # ------------------------------------------------------------ inspection
    def detect(self, path: Path) -> Detection:
        from msoffcrypto import exceptions as mse

        head = path.open("rb").read(8)
        if head.startswith(ZIP_MAGIC):
            return self._detect_plain_package(path)

        try:
            office, fh = _office_file(path)
        except mse.ParseError as exc:  # pragma: no cover - malformed OLE
            raise CorruptFileError(f"Damaged Office container: {exc}") from exc
        with fh:
            kind = getattr(office, "type", "unknown")
            if not office.is_encrypted():
                return Detection(
                    path=path,
                    format_id=self.format_id,
                    format_name=self.format_name,
                    protection=Protection.NONE,
                    removability=Removability.NOT_PROTECTED,
                    detail="This Office container is not encrypted.",
                )
            algorithm = {
                "agile": "ECMA-376 agile (AES-CBC, Office 2010+)",
                "standard": "ECMA-376 standard (AES-128, Office 2007)",
                "extensible": "ECMA-376 extensible encryption",
            }.get(kind, f"ECMA-376 ({kind})")
            if kind == "extensible":
                return Detection(
                    path=path,
                    format_id=self.format_id,
                    format_name=self.format_name,
                    protection=Protection.DRM,
                    removability=Removability.UNSUPPORTED,
                    algorithm=algorithm,
                    detail=(
                        "This document uses extensible encryption (typically Information "
                        "Rights Management). The key is held by a rights server, not by a "
                        "password, so it cannot be removed offline."
                    ),
                )
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.USER_PASSWORD,
                removability=Removability.REMOVABLE,
                algorithm=algorithm,
                detail="Encrypted with a password. Supply it to write a decrypted copy.",
            )

    def _detect_plain_package(self, path: Path) -> Detection:
        """An unencrypted OOXML zip: look for editing restrictions."""
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
                found: list[str] = []
                for part, (marker, label) in _RESTRICTION_MARKERS.items():
                    if part in names:
                        try:
                            blob = zf.read(part)
                        except (KeyError, zipfile.BadZipFile):  # pragma: no cover
                            continue
                        if marker.encode() in blob:
                            found.append(label)
        except zipfile.BadZipFile as exc:
            raise CorruptFileError(f"Damaged Office package: {exc}") from exc

        if found:
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.OWNER_RESTRICTIONS,
                removability=Removability.REFUSED_BY_POLICY,
                algorithm="OOXML editing restriction (hash-verified, content not encrypted)",
                detail=(
                    f"The contents are not encrypted; the file carries {', '.join(found)}. "
                    "Removing that only means deleting an XML element, which this tool will "
                    "not do -- it would be a bypass, not a decryption. Open the file in the "
                    "original application and use its own 'Stop Protection' command."
                ),
            )
        return Detection(
            path=path,
            format_id=self.format_id,
            format_name=self.format_name,
            protection=Protection.NONE,
            removability=Removability.NOT_PROTECTED,
            detail="Not protected; this is a plain Office package.",
        )

    # ---------------------------------------------------------------- action
    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:
        from msoffcrypto import exceptions as mse

        head = source.open("rb").read(8)
        if head.startswith(ZIP_MAGIC):
            detection = self._detect_plain_package(source)
            if detection.removability is Removability.REFUSED_BY_POLICY:
                raise PolicyRefusedError(detection.detail, remediation=None)
            raise UnsupportedFormatError(
                "This Office file is not encrypted, so there is nothing to decrypt.",
                remediation="Run `fpr inspect` to see what protection a file carries.",
            )

        office, fh = _office_file(source)
        buffer = io.BytesIO()
        with fh:
            if not office.is_encrypted():
                raise UnsupportedFormatError(
                    "This Office file is not encrypted, so there is nothing to decrypt."
                )
            kind = getattr(office, "type", "unknown")
            if kind not in ("agile", "standard"):
                raise UnsupportedFormatError(
                    f"Unsupported Office encryption type: {kind}.",
                    remediation="Only ECMA-376 agile and standard password encryption are supported.",
                )
            with secret.expose() as password:
                try:
                    office.load_key(password=password, verify_password=True)
                except mse.InvalidKeyError as exc:
                    raise IncorrectPasswordError() from exc
                except mse.DecryptionError as exc:
                    raise CorruptFileError(f"Could not prepare decryption: {exc}") from exc
            try:
                # verify_integrity checks the HMAC over the encrypted package,
                # which catches truncation and tampering before we write anything.
                office.decrypt(buffer, verify_integrity=(kind == "agile"))
            except mse.InvalidKeyError as exc:
                # After a verified password this means the payload is damaged,
                # not that the user typed the wrong thing -- say so accurately.
                raise CorruptFileError(
                    f"The password was correct but the encrypted payload failed its integrity "
                    f"check: {exc}",
                    remediation="The file is damaged or truncated. Try re-downloading it.",
                ) from exc
            except mse.DecryptionError as exc:
                raise CorruptFileError(f"Decryption failed: {exc}") from exc

        payload = buffer.getvalue()
        expectations = _zip_expectations(io.BytesIO(payload))
        destination.write_bytes(payload)

        algorithm = {
            "agile": "ECMA-376 agile (AES-CBC, Office 2010+)",
            "standard": "ECMA-376 standard (AES-128, Office 2007)",
        }.get(kind, kind)
        return RemovalEvidence(
            protection=Protection.USER_PASSWORD,
            algorithm=algorithm,
            expectations=expectations,
            warnings=(),
        )

    # ------------------------------------------------------------ assurance
    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:
        with output.open("rb") as fh:
            head = fh.read(8)
        if head.startswith(OLE_MAGIC):
            raise VerificationError(
                "The written file is still an encrypted Office container. It has been discarded."
            )
        if not head.startswith(ZIP_MAGIC):
            raise VerificationError(
                "The written file is not a valid Office package. It has been discarded."
            )
        try:
            actual = _zip_expectations(output)
        except zipfile.BadZipFile as exc:
            raise VerificationError(
                f"The written Office package is not a readable ZIP: {exc}. It has been discarded."
            ) from exc

        for key in ("entries", "names_digest", "crc_digest", "has_content_types"):
            if evidence.expectations.get(key) != actual.get(key):
                raise VerificationError(
                    f"Output verification failed: {key} changed during decryption "
                    f"(expected {evidence.expectations.get(key)!r}, got {actual.get(key)!r}). "
                    "The output has been discarded.",
                    remediation="Please report this with the file type and tool version.",
                )
        return {
            "encrypted": "false",
            "package_parts": actual["entries"],
            "content_types_present": actual["has_content_types"],
            "parts_crc_digest": actual["crc_digest"][:16],
        }


# ------------------------------------------------------------------ helpers
def _zip_expectations(source: Path | io.BytesIO) -> dict[str, str]:
    """Names + CRCs of every part. Cheap, and sensitive to any content change."""
    import hashlib

    with zipfile.ZipFile(source) as zf:
        infos = sorted(zf.infolist(), key=lambda i: i.filename)
        names = "\n".join(i.filename for i in infos)
        crcs = "\n".join(f"{i.filename}:{i.CRC:08x}:{i.file_size}" for i in infos)
        return {
            "entries": str(len(infos)),
            "names_digest": hashlib.sha256(names.encode()).hexdigest(),
            "crc_digest": hashlib.sha256(crcs.encode()).hexdigest(),
            "has_content_types": "true"
            if _CONTENT_TYPES in {i.filename for i in infos}
            else "false",
        }


def _zip_is_ooxml(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            return _CONTENT_TYPES in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def _ole_is_ooxml(path: Path) -> bool:
    """True when this OLE container wraps an encrypted OOXML package."""
    try:
        import olefile
    except ImportError:  # pragma: no cover - olefile is a msoffcrypto dependency
        return False
    try:
        with olefile.OleFileIO(str(path)) as ole:
            return bool(ole.exists("EncryptedPackage") and ole.exists("EncryptionInfo"))
    except (OSError, ValueError):
        return False
