"""PDF adapter, built on pikepdf/qpdf.

Scope
-----
* **Removable**: the standard security handler (``/Filter /Standard``) at every
  revision qpdf implements -- R2/R3 (RC4 40/128-bit), R4 (RC4-128 or AES-128),
  R5 and R6 (AES-256). Supplying the user *or* the owner password decrypts the
  document, and re-saving without an ``encryption`` argument writes a plain PDF.
* **Refused by policy**: a document whose *user* password is empty but which
  carries permission flags. qpdf will happily open it with ``""`` and drop the
  flags, and every "PDF unlocker" on the web does exactly that. We do not:
  clearing restrictions you were not given the owner password for is a bypass,
  not a removal. Pass ``--remove-restrictions`` *and* the correct owner
  password and the adapter will do it; supply neither and it refuses.
* **Unsupported**: certificate/public-key security (``/Filter /Adobe.PubSec``)
  and any third-party DRM handler. These are not password protection.

Why the output is trustworthy
-----------------------------
``remove`` records the decoded content stream of every page (sampled on very
large documents), the page count, and whether document info/XMP metadata were
present. ``verify`` re-opens the written file from disk, asserts it is not
encrypted, and re-computes the same digests. A PDF that came out with the right
page count but scrambled content would fail verification and be deleted.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..errors import (
    CorruptFileError,
    IncorrectPasswordError,
    UnsupportedFormatError,
    VerificationError,
)
from ..secret import Secret
from ..types import Detection, FormatId, Protection, Removability
from .base import Adapter, AdapterOptions, ProtectEvidence, RemovalEvidence

__all__ = ["PdfAdapter"]

_PDF_MAGIC = b"%PDF-"
_TAIL_WINDOW = 256 * 1024
_HEAD_WINDOW = 256 * 1024

VERIFY_PAGE_CAP = 400
"""Above this page count we hash a deterministic sample instead of every page.

Hashing 5 000 pages twice turns a two-second job into a minute for no extra
assurance; the sample is recorded in the evidence so the report never implies
a full check happened when it did not.
"""


def _describe_algorithm(r: int | None, v: int | None, stream_method: object = None) -> str | None:
    """Map the standard security handler's R/V to a human-readable cipher."""
    if r is None:
        return None
    method = str(stream_method).rsplit(".", 1)[-1].lower() if stream_method else ""
    if r == 2:
        return "RC4 40-bit (PDF 1.1, R2)"
    if r == 3:
        return "RC4 128-bit (PDF 1.4, R3)"
    if r == 4:
        if "aes" in method:
            return "AES-128 (PDF 1.6, R4/V4)"
        if method:
            return f"RC4 128-bit (PDF 1.6, R4/V4, {method})"
        return "RC4-128 or AES-128 (PDF 1.6, R4/V4)"
    if r == 5:
        return "AES-256 (Adobe extension level 3, R5 - deprecated)"
    if r == 6:
        return "AES-256 (PDF 2.0, R6)"
    return f"standard security handler R{r}" + (f"/V{v}" if v else "")


def _scan_encrypt_params(path: Path) -> dict[str, Any]:
    """Best-effort read of the encryption dictionary *without* a password.

    The /Encrypt dictionary is never itself encrypted, so for the overwhelming
    majority of files it is plain ASCII somewhere in the byte stream. We look
    only in a bounded head and tail window so this stays O(1) on huge files,
    and we return ``{}`` rather than guessing when the pattern is not found.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            head = fh.read(_HEAD_WINDOW)
            if size > _HEAD_WINDOW:
                fh.seek(max(0, size - _TAIL_WINDOW))
                tail = fh.read(_TAIL_WINDOW)
            else:
                tail = b""
    except OSError:
        return {}

    data = head + tail
    out: dict[str, Any] = {}
    if b"/Adobe.PubSec" in data:
        out["handler"] = "Adobe.PubSec"
        return out
    if b"/Standard" not in data:
        return out
    out["handler"] = "Standard"
    # Anchor the search near the handler name to avoid picking up /V or /R
    # from unrelated objects such as fonts.
    anchor = data.find(b"/Standard")
    window = data[max(0, anchor - 512) : anchor + 1024]
    for key, name in (
        (rb"/R\s+(\d+)", "R"),
        (rb"/V\s+(\d+)", "V"),
        (rb"/Length\s+(\d+)", "Length"),
    ):
        m = re.search(key, window)
        if m:
            out[name] = int(m.group(1))
    m = re.search(rb"/P\s+(-?\d+)", window)
    if m:
        out["P"] = int(m.group(1))
    return out


def _permission_summary(allow: Any) -> str:
    denied = [name for name in getattr(allow, "_fields", ()) if not getattr(allow, name)]
    return ", ".join(denied) if denied else "none"


class PdfAdapter(Adapter):
    format_id = FormatId.PDF
    format_name = "PDF"
    extensions = (".pdf",)

    # ------------------------------------------------------------- identity
    @classmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        # A conforming PDF starts with %PDF-. Some real-world files carry junk
        # before the header; qpdf tolerates up to 1024 bytes of it, so we do too.
        return head.startswith(_PDF_MAGIC) or _PDF_MAGIC in head[:1024]

    # ------------------------------------------------------------ inspection
    def detect(self, path: Path) -> Detection:
        import pikepdf

        raw = _scan_encrypt_params(path)
        if raw.get("handler") == "Adobe.PubSec":
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.UNKNOWN,
                removability=Removability.UNSUPPORTED,
                algorithm="public-key security handler (Adobe.PubSec)",
                detail=(
                    "This PDF is encrypted to a certificate, not a password. It can only be "
                    "opened with the matching private key from your certificate store."
                ),
            )

        try:
            with pikepdf.open(path) as pdf:
                if not pdf.is_encrypted:
                    return Detection(
                        path=path,
                        format_id=self.format_id,
                        format_name=self.format_name,
                        protection=Protection.NONE,
                        removability=Removability.NOT_PROTECTED,
                        detail=f"Not protected; {len(pdf.pages)} page(s).",
                    )
                # We got in with an empty password, so the content is readable
                # by anyone. Which empty password worked tells us what kind of
                # file this is.
                enc = pdf.encryption
                algorithm = _describe_algorithm(
                    getattr(enc, "R", None),
                    getattr(enc, "V", None),
                    getattr(enc, "stream_method", None),
                )
                denied = _permission_summary(pdf.allow)
                if pdf.owner_password_matched:
                    # The *owner* password is the empty string. Every PDF tool
                    # in existence can open and re-save this file, so its
                    # restrictions are decorative. There may still be a separate
                    # open password, which we cannot see from here.
                    detail = (
                        "This PDF's owner password is empty, so any tool can open and re-save "
                        f"it and its restrictions (denied: {denied}) are not enforceable. "
                        "Re-run with --remove-restrictions to write a plain copy; if the file "
                        "also has a separate open password, supply that."
                    )
                else:
                    detail = (
                        f"No password is needed to read this PDF; it carries permission "
                        f"restrictions (denied: {denied}). Removing them requires the owner "
                        f"password and the --remove-restrictions flag."
                    )
                return Detection(
                    path=path,
                    format_id=self.format_id,
                    format_name=self.format_name,
                    protection=Protection.OWNER_RESTRICTIONS,
                    removability=Removability.REMOVABLE_WITH_OWNER_PASSWORD,
                    algorithm=algorithm,
                    detail=detail,
                )
        except pikepdf.PasswordError:
            algorithm = _describe_algorithm(raw.get("R"), raw.get("V"))
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.USER_PASSWORD,
                removability=Removability.REMOVABLE,
                algorithm=algorithm,
                detail="Encrypted. Supply the open (user) password or the owner password.",
            )
        except pikepdf.PdfError as exc:
            raise CorruptFileError(
                f"This file is not a readable PDF: {exc}",
                remediation="The file may be truncated or damaged. Try re-downloading it.",
            ) from exc

    # ---------------------------------------------------------------- action
    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:
        import pikepdf

        with secret.expose() as password:
            try:
                pdf = pikepdf.open(source, password=password)
            except pikepdf.PasswordError as exc:
                raise IncorrectPasswordError() from exc
            except pikepdf.PdfError as exc:
                raise CorruptFileError(f"Could not read the PDF: {exc}") from exc

        with pdf:
            if not pdf.is_encrypted:
                raise UnsupportedFormatError(
                    "This PDF is not encrypted, so there is nothing to decrypt.",
                    remediation="Use `fpr inspect` to see what protection a file carries.",
                )

            owner_matched = bool(pdf.owner_password_matched)
            enc = pdf.encryption
            algorithm = _describe_algorithm(
                getattr(enc, "R", None),
                getattr(enc, "V", None),
                getattr(enc, "stream_method", None),
            )

            # Distinguish "decrypting a document I have the password for" from
            # "stripping flags off a document anyone can already read".
            #
            # Two facts settle it. Does the document open with an empty
            # password (so the content is public)? And did the password the
            # user supplied match as the *user* password (so they hold the key
            # to the content, whatever else is true)? Only the combination
            # "public content" + "did not supply the user password" is a
            # restriction removal.
            #
            # pikepdf's ``encryption.user_password`` cannot answer this: it
            # echoes the password that was supplied, not the document's own.
            user_matched = bool(pdf.user_password_matched)
            restriction_only = _opens_without_password(source) and not user_matched

            if restriction_only and not options.allow_restriction_removal:
                raise _restriction_policy_error(owner_known=owner_matched)

            protection = (
                Protection.OWNER_RESTRICTIONS
                if restriction_only
                else (Protection.BOTH if _has_restrictions(pdf.allow) else Protection.USER_PASSWORD)
            )

            expectations = _capture_expectations(pdf)
            warnings: list[str] = []
            if getattr(enc, "R", 0) in (2, 3):
                warnings.append(
                    "The source used RC4, which is obsolete. The output is not encrypted at all, "
                    "so store it somewhere you trust."
                )
            if restriction_only:
                warnings.append(
                    "Permission restrictions were cleared using the owner password you supplied."
                )

            try:
                pdf.save(destination)
            except pikepdf.PdfError as exc:  # pragma: no cover - disk or stream corruption
                raise CorruptFileError(f"Failed while writing the decrypted PDF: {exc}") from exc

        return RemovalEvidence(
            protection=protection,
            algorithm=algorithm,
            expectations=expectations,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------ assurance
    def protect(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> ProtectEvidence:
        """Encrypt with AES-256 (R6), the strongest the PDF spec defines.

        The same password is set as both the user and the owner password. Using
        a different owner password would create a second credential that also
        opens the file, which is one more thing to lose for no benefit here.
        """
        import pikepdf

        try:
            with pikepdf.open(source) as pdf:
                expected = _capture_expectations(pdf)
                with secret.expose() as password:
                    pdf.save(
                        destination,
                        encryption=pikepdf.Encryption(
                            user=password, owner=password, R=6, aes=True, metadata=True
                        ),
                    )
        except pikepdf.PasswordError as exc:  # pragma: no cover - guarded by the engine
            raise IncorrectPasswordError(f"{source.name} is already encrypted.") from exc
        except pikepdf.PdfError as exc:
            raise CorruptFileError(f"{source.name} could not be read as a PDF: {exc}") from exc

        return ProtectEvidence(
            protection=Protection.USER_PASSWORD,
            algorithm="AES-256 (PDF 2.0, R6)",
            expected=expected,
        )

    def verify_protected(
        self, output: Path, secret: Secret, evidence: ProtectEvidence
    ) -> dict[str, str]:
        """Prove the file is locked, and that the password opens it unchanged.

        Two separate claims, both checked: opening without a password must
        fail, and opening *with* it must give back the content we started with.
        A file that is encrypted but no longer holds the original pages is not
        a success.
        """
        import pikepdf

        if _opens_without_password(output):
            raise VerificationError(
                "The written PDF opens without a password. The output has been discarded."
            )

        try:
            with secret.expose() as password, pikepdf.open(output, password=password) as pdf:
                actual = _capture_expectations(pdf)
        except pikepdf.PasswordError as exc:
            raise VerificationError(
                "The written PDF could not be opened with the password it was just given. "
                "The output has been discarded."
            ) from exc
        except pikepdf.PdfError as exc:
            raise VerificationError(
                f"The written PDF could not be re-opened: {exc}. The output has been discarded."
            ) from exc

        _compare(evidence.expected, actual, "pages")
        _compare(evidence.expected, actual, "content_digest")
        return {
            "encrypted": "true",
            "opens": "true",
            "pages": actual.get("pages", "?"),
            "content_digest": actual.get("content_digest", "")[:16],
            "content_scope": actual.get("content_scope", ""),
        }

    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:
        import pikepdf

        try:
            with pikepdf.open(output) as pdf:
                if pdf.is_encrypted:
                    raise VerificationError(
                        "The written PDF is still encrypted. The output has been discarded."
                    )
                actual = _capture_expectations(pdf)
        except pikepdf.PasswordError as exc:
            raise VerificationError(
                "The written PDF still asks for a password. The output has been discarded."
            ) from exc
        except pikepdf.PdfError as exc:
            raise VerificationError(
                f"The written PDF could not be re-opened: {exc}. The output has been discarded."
            ) from exc

        _compare(evidence.expectations, actual, "pages")
        _compare(evidence.expectations, actual, "content_digest")
        _compare(evidence.expectations, actual, "content_scope")
        proof = {
            "encrypted": "false",
            "pages": actual.get("pages", "?"),
            "content_digest": actual.get("content_digest", "")[:16],
            "content_scope": actual.get("content_scope", ""),
        }
        for key in ("docinfo_keys", "has_xmp"):
            if key in evidence.expectations:
                if evidence.expectations[key] != actual.get(key):
                    # Metadata differences are reported, not fatal: qpdf updates
                    # the XMP "producer" trail when it rewrites a document.
                    proof[f"{key}_changed"] = "true"
                else:
                    proof[key] = actual.get(key, "")
        return proof


def _opens_without_password(path: Path) -> bool:
    """True when anyone can read this document without supplying a password."""
    import pikepdf

    try:
        with pikepdf.open(path):
            return True
    except pikepdf.PasswordError:
        return False
    except pikepdf.PdfError:  # pragma: no cover - already opened once successfully
        return False


def _has_restrictions(allow: Any) -> bool:
    return any(not getattr(allow, name) for name in getattr(allow, "_fields", ()))


def _restriction_policy_error(*, owner_known: bool) -> Exception:
    from ..errors import PolicyRefusedError

    if owner_known:
        return PolicyRefusedError(
            "This PDF is not encrypted for reading; it only carries permission restrictions.",
            remediation=(
                "Re-run with --remove-restrictions to clear them. You supplied the correct "
                "owner password, so this is permitted."
            ),
        )
    return PolicyRefusedError(
        "This PDF can already be opened without a password; it only carries permission "
        "restrictions, and the password you supplied is not its owner password.",
        remediation=(
            "Supply the owner password together with --remove-restrictions. "
            "This tool will not strip restriction flags from a document you cannot prove you own."
        ),
    )


def _capture_expectations(pdf: Any) -> dict[str, str]:
    """Cheap, content-sensitive invariants used to prove the output is intact."""
    pages = list(pdf.pages)
    count = len(pages)
    if count <= VERIFY_PAGE_CAP:
        indices = range(count)
        scope = f"all {count} page(s)"
    else:
        step = max(1, count // VERIFY_PAGE_CAP)
        indices = range(0, count, step)
        scope = f"{len(range(0, count, step))} of {count} page(s), every {step}"

    digest = hashlib.sha256()
    for i in indices:
        digest.update(i.to_bytes(4, "big"))
        digest.update(page_content_bytes(pages[i]))

    out = {
        "pages": str(count),
        "content_digest": digest.hexdigest(),
        "content_scope": scope,
    }
    try:
        out["docinfo_keys"] = ",".join(sorted(str(k) for k in pdf.docinfo))
    except Exception:  # noqa: BLE001 - docinfo is optional
        out["docinfo_keys"] = ""
    out["has_xmp"] = "true" if "/Metadata" in pdf.Root else "false"
    return out


def page_content_bytes(page: Any) -> bytes:
    """Decoded content stream(s) of one page.

    Decoded, not raw, so that a re-compression by qpdf does not look like a
    content change -- and so that a genuine content change still does.
    """
    import pikepdf

    try:
        contents = page.obj.get("/Contents")
    except Exception:  # noqa: BLE001 - a malformed page dictionary
        return b"<unreadable>"
    if contents is None:
        return b"<no-contents>"
    try:
        if isinstance(contents, pikepdf.Array):
            return b"\n".join(bytes(item.read_bytes()) for item in contents)
        return bytes(contents.read_bytes())
    except Exception:  # noqa: BLE001 - damaged or unsupported stream filter
        return b"<unreadable>"


def _compare(expected: dict[str, str], actual: dict[str, str], key: str) -> None:
    if key not in expected:
        return
    if expected[key] != actual.get(key):
        raise VerificationError(
            f"Output verification failed: {key} changed during decryption "
            f"(expected {expected[key]!r}, got {actual.get(key)!r}). The output has been discarded.",
            remediation="Please report this with the file type and tool version; it is a bug.",
        )
