"""Legacy binary Office documents (.doc / .xls / .ppt, Office 97-2003).

Status: **experimental, and labelled as such everywhere it is surfaced.**

The decryption itself is msoffcrypto's, which is mature. What is missing here
is *our* evidence: there is no way to generate an RC4/CryptoAPI-encrypted BIFF8
or Word 97 document from open tooling on a build machine, and no safely
redistributable sample exists, so this path has no fixture-backed test. The
project's rule is that an untested path does not get to look finished, so it is
gated behind ``--experimental`` and reported as experimental in the output.

Detection, by contrast, *is* tested: identifying one of these containers and
saying "this is a legacy Office document" needs no sample we cannot build.

Removing a legacy document's password produces a legacy document. Converting
.doc to .docx is a different product and is explicitly out of scope.
"""

from __future__ import annotations

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
from .ooxml import OLE_MAGIC

__all__ = ["LegacyOfficeAdapter"]

_LEGACY_STREAMS = {
    "WordDocument": ("Microsoft Word 97-2003 document", (".doc", ".dot")),
    "Workbook": ("Microsoft Excel 97-2003 workbook", (".xls", ".xlt")),
    "Book": ("Microsoft Excel 5.0/95 workbook", (".xls",)),
    "PowerPoint Document": ("Microsoft PowerPoint 97-2003 presentation", (".ppt", ".pot", ".pps")),
}


def _legacy_kind(path: Path) -> tuple[str, tuple[str, ...]] | None:
    try:
        import olefile
    except ImportError:  # pragma: no cover
        return None
    try:
        with olefile.OleFileIO(str(path)) as ole:
            for stream, info in _LEGACY_STREAMS.items():
                if ole.exists(stream):
                    return info
    except (OSError, ValueError):
        return None
    return None


class LegacyOfficeAdapter(Adapter):
    format_id = FormatId.LEGACY_OFFICE
    format_name = "Legacy Office 97-2003 (experimental)"
    extensions = (".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".pps")

    @classmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        return head.startswith(OLE_MAGIC) and _legacy_kind(path) is not None

    def detect(self, path: Path) -> Detection:
        import msoffcrypto
        from msoffcrypto import exceptions as mse

        kind = _legacy_kind(path)
        name = kind[0] if kind else "Legacy Office document"
        try:
            with path.open("rb") as fh:
                office = msoffcrypto.OfficeFile(fh)
                encrypted = bool(office.is_encrypted())
                scheme = getattr(office, "type", "unknown")
        except mse.FileFormatError as exc:
            raise UnsupportedFormatError(
                f"{name}: unrecognised internal structure ({exc})."
            ) from exc
        except mse.ParseError as exc:
            raise CorruptFileError(f"{name}: damaged container ({exc}).") from exc

        if not encrypted:
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=name,
                protection=Protection.NONE,
                removability=Removability.NOT_PROTECTED,
                detail=f"{name}, not encrypted.",
            )
        return Detection(
            path=path,
            format_id=self.format_id,
            format_name=name,
            protection=Protection.USER_PASSWORD,
            removability=Removability.REMOVABLE,
            algorithm=f"legacy Office encryption ({scheme})",
            detail=(
                f"{name}, password-encrypted. Support for these files is EXPERIMENTAL: it has "
                "no automated test coverage because no sample of this format can be generated "
                "or redistributed. Pass --experimental to attempt it, and check the result."
            ),
        )

    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:
        import msoffcrypto
        from msoffcrypto import exceptions as mse

        if not options.experimental:
            raise PolicyRefusedError(
                "Legacy Office 97-2003 decryption is experimental and has no automated test "
                "coverage, so it is off by default.",
                remediation="Re-run with --experimental if you accept that, and verify the "
                "output opens correctly before deleting the original.",
            )

        with source.open("rb") as fh:
            office = msoffcrypto.OfficeFile(fh)
            if not office.is_encrypted():
                raise UnsupportedFormatError("This document is not encrypted.")
            with secret.expose() as password:
                try:
                    office.load_key(password=password, verify_password=True)
                except mse.InvalidKeyError as exc:
                    raise IncorrectPasswordError() from exc
                except mse.DecryptionError as exc:
                    raise CorruptFileError(f"Could not prepare decryption: {exc}") from exc
            with destination.open("wb") as out:
                try:
                    office.decrypt(out)
                except mse.InvalidKeyError as exc:
                    raise IncorrectPasswordError() from exc
                except mse.DecryptionError as exc:
                    raise CorruptFileError(f"Decryption failed: {exc}") from exc

        kind = _legacy_kind(source)
        return RemovalEvidence(
            protection=Protection.USER_PASSWORD,
            algorithm="legacy Office encryption",
            expectations={"expected_stream": (kind[0] if kind else "")},
            warnings=(
                "Legacy Office support is experimental and untested in CI. Open the output in "
                "the original application and confirm it is intact before deleting the source.",
            ),
        )

    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:
        import msoffcrypto
        from msoffcrypto import exceptions as mse

        try:
            with output.open("rb") as fh:
                office = msoffcrypto.OfficeFile(fh)
                if office.is_encrypted():
                    raise VerificationError(
                        "The written document is still encrypted. The output has been discarded."
                    )
        except (mse.FileFormatError, mse.ParseError) as exc:
            raise VerificationError(
                f"The written document could not be re-opened: {exc}. "
                "The output has been discarded."
            ) from exc
        kind = _legacy_kind(output)
        if kind is None:
            raise VerificationError(
                "The written document no longer contains a recognisable Office stream. "
                "The output has been discarded."
            )
        return {"encrypted": "false", "container": kind[0], "coverage": "experimental"}
