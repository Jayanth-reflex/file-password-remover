"""ZIP adapter: legacy ZipCrypto and WinZip AES archives.

Two encryption schemes live inside the ZIP format and they behave very
differently, so the adapter reports which one it found:

**ZipCrypto** (the 1990 "standard" scheme) is broken by design -- it is a
stream cipher with a 12-byte header whose last byte is a *one-byte* password
check. A wrong password therefore passes the check roughly once every 256
attempts, and the error only shows up later as a CRC mismatch. The adapter
never reports success on a CRC failure; it reports the ambiguity honestly.

**WinZip AES** (AE-1/AE-2, 128/192/256-bit) derives keys with PBKDF2-HMAC-SHA1
and authenticates each entry with HMAC-SHA1. A wrong password is detected by a
2-byte verifier (1 in 65 536 false accepts) and then definitively by the
authentication code, which ``pyzipper`` checks on read. Note that AE-2 entries
store a CRC of zero by specification, so per-entry verification here uses a
SHA-256 of the decrypted bytes rather than the stored CRC.

The output is a new archive with the same entries, names, timestamps, external
attributes, compression methods and comments -- just without encryption.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

from ..errors import (
    CorruptFileError,
    IncorrectPasswordError,
    UnsupportedFormatError,
    VerificationError,
)
from ..secret import Secret
from ..types import Detection, FormatId, Protection, Removability
from .base import Adapter, AdapterOptions, RemovalEvidence

__all__ = ["ZipAdapter", "MAX_TOTAL_UNCOMPRESSED", "MAX_COMPRESSION_RATIO"]

ZIP_MAGIC = b"PK\x03\x04"
EMPTY_ZIP_MAGIC = b"PK\x05\x06"
_AES_EXTRA_ID = 0x9901
_AES_COMPRESS_TYPE = 99
_CHUNK = 1 << 20

MAX_TOTAL_UNCOMPRESSED = 16 << 30
"""Refuse archives that expand past 16 GiB. A decompression bomb is a denial of
service against the person running the tool, so it is capped rather than
streamed forever. Override with ``--max-expanded-size``."""

MAX_COMPRESSION_RATIO = 2000
"""Per-entry expansion ratio ceiling; 1000:1 is achievable with legitimate data
(sparse logs), 2000:1 essentially is not."""

_AES_STRENGTH = {1: "AES-128", 2: "AES-192", 3: "AES-256"}


def _aes_info(info: zipfile.ZipInfo) -> tuple[str, int] | None:
    """Parse the 0x9901 extra field: returns (cipher name, real method)."""
    extra = info.extra or b""
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        body = extra[pos + 4 : pos + 4 + size]
        if header_id == _AES_EXTRA_ID and size >= 7:
            _version, _vendor, strength, method = struct.unpack("<H2sBH", body[:7])
            return _AES_STRENGTH.get(strength, f"AES (strength id {strength})"), method
        pos += 4 + size
    return None


def _strip_aes_extra(extra: bytes) -> bytes:
    """Remove the 0x9901 record; it describes encryption the output will not have."""
    out = bytearray()
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        if header_id != _AES_EXTRA_ID:
            out += extra[pos : pos + 4 + size]
        pos += 4 + size
    return bytes(out)


def _is_encrypted(info: zipfile.ZipInfo) -> bool:
    return bool(info.flag_bits & 0x1)


def _zipcrypto_ambiguity(info: zipfile.ZipInfo, what: str) -> IncorrectPasswordError:
    """The honest message for ZipCrypto's one-byte password check.

    ZipCrypto lets roughly 1 in 256 wrong passwords past its verifier, and the
    mistake only shows up as unusable data further in. Claiming "damaged file"
    would send the user chasing the wrong problem, and claiming a definite
    wrong password would overstate what we know -- so the message says both,
    with the likely cause first.
    """
    return IncorrectPasswordError(
        f"Entry {info.filename!r} {what}. With ZipCrypto this almost always means the "
        "password is wrong: its one-byte password check lets about 1 in 256 wrong passwords "
        "through, and the error only appears when the data is used. It can also mean the "
        "archive is damaged.",
        remediation="Re-check the password. If it is definitely correct, the archive is damaged.",
    )


class ZipAdapter(Adapter):
    format_id = FormatId.ZIP
    format_name = "ZIP archive"
    extensions = (".zip",)

    # ------------------------------------------------------------- identity
    @classmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        # OOXML packages are ZIPs too; their adapter is registered ahead of
        # this one, so anything else that is a ZIP belongs here.
        return head.startswith((ZIP_MAGIC, EMPTY_ZIP_MAGIC))

    # ------------------------------------------------------------ inspection
    def detect(self, path: Path) -> Detection:
        import pyzipper

        try:
            with pyzipper.AESZipFile(path) as zf:
                infos = zf.infolist()
                encrypted = [i for i in infos if _is_encrypted(i)]
                ciphers: set[str] = set()
                for info in encrypted:
                    aes = _aes_info(info)
                    ciphers.add(aes[0] if aes else "ZipCrypto (legacy)")
        except (zipfile.BadZipFile, OSError) as exc:
            raise CorruptFileError(
                f"This file is not a readable ZIP archive: {exc}",
                remediation="The archive may be truncated or damaged.",
            ) from exc

        if not encrypted:
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.NONE,
                removability=Removability.NOT_PROTECTED,
                detail=f"No encrypted entries; {len(infos)} entr(ies) total.",
            )

        algorithm = ", ".join(sorted(ciphers))
        partial = len(encrypted) < len(infos)
        detail = (
            f"{len(encrypted)} of {len(infos)} entries are encrypted with {algorithm}."
            if partial
            else f"All {len(infos)} entries are encrypted with {algorithm}."
        )
        if "ZipCrypto (legacy)" in ciphers:
            detail += (
                " ZipCrypto's password check is one byte wide, so a wrong password is only "
                "detected reliably by the CRC of each entry."
            )
        return Detection(
            path=path,
            format_id=self.format_id,
            format_name=self.format_name,
            protection=Protection.USER_PASSWORD,
            removability=Removability.REMOVABLE,
            algorithm=algorithm,
            detail=detail,
        )

    # ---------------------------------------------------------------- action
    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:
        import pyzipper

        digests: list[str] = []
        total = 0
        ciphers: set[str] = set()
        warnings: list[str] = []

        with pyzipper.AESZipFile(source) as zin:
            infos = zin.infolist()
            if not any(_is_encrypted(i) for i in infos):
                raise UnsupportedFormatError(
                    "No entry in this archive is encrypted, so there is nothing to decrypt."
                )
            with secret.expose_bytes() as raw:
                zin.setpassword(raw)

                with zipfile.ZipFile(destination, "w", allowZip64=True) as zout:
                    zout.comment = zin.comment
                    for info in infos:
                        aes = _aes_info(info)
                        if _is_encrypted(info):
                            ciphers.add(aes[0] if aes else "ZipCrypto (legacy)")
                        total += self._copy_entry(zin, zout, info, aes, digests, total)

        if "ZipCrypto (legacy)" in ciphers:
            warnings.append(
                "The source used ZipCrypto, which is cryptographically broken. Treat the "
                "original as compromised if it ever left your control."
            )

        expectations = {
            "entries": str(len(infos)),
            "content_digest": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
            "total_bytes": str(total),
        }
        return RemovalEvidence(
            protection=Protection.USER_PASSWORD,
            algorithm=", ".join(sorted(ciphers)) or None,
            expectations=expectations,
            warnings=tuple(warnings),
        )

    def _copy_entry(
        self,
        zin: zipfile.ZipFile,
        zout: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        aes: tuple[str, int] | None,
        digests: list[str],
        running_total: int,
    ) -> int:
        """Stream one entry across, recording a digest of its plaintext."""
        out_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
        out_info.compress_type = (
            info.compress_type
            if info.compress_type != _AES_COMPRESS_TYPE
            else (aes[1] if aes else zipfile.ZIP_DEFLATED)
        )
        out_info.comment = info.comment
        out_info.extra = _strip_aes_extra(info.extra or b"")
        out_info.create_system = info.create_system
        out_info.external_attr = info.external_attr
        out_info.internal_attr = info.internal_attr
        # Drop the encryption bit (0x1) and the data-descriptor bit (0x8): we
        # write sizes up front, so a descriptor would be wrong.
        out_info.flag_bits = info.flag_bits & ~0x9

        if info.is_dir():
            zout.writestr(out_info, b"")
            digests.append(f"{info.filename}:<dir>")
            return 0

        digest = hashlib.sha256()
        written = 0
        try:
            with zin.open(info, "r") as src, zout.open(out_info, "w") as dst:
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if running_total + written > MAX_TOTAL_UNCOMPRESSED:
                        raise UnsupportedFormatError(
                            "This archive expands beyond the safety limit "
                            f"({MAX_TOTAL_UNCOMPRESSED >> 30} GiB).",
                            remediation="Extract it manually if you trust its contents.",
                        )
                    if (
                        info.compress_size
                        and written // max(info.compress_size, 1) > MAX_COMPRESSION_RATIO
                    ):
                        raise UnsupportedFormatError(
                            f"Entry {info.filename!r} expands more than "
                            f"{MAX_COMPRESSION_RATIO}:1, which looks like a decompression bomb.",
                            remediation="Extract it manually if you trust its contents.",
                        )
                    digest.update(chunk)
                    dst.write(chunk)
        except RuntimeError as exc:
            # pyzipper signals a rejected password with RuntimeError.
            if "password" in str(exc).lower():
                raise IncorrectPasswordError() from exc
            raise CorruptFileError(f"Could not read {info.filename!r}: {exc}") from exc
        except zipfile.BadZipFile as exc:
            if "CRC" in str(exc).upper() and _is_encrypted(info):
                raise _zipcrypto_ambiguity(info, "failed its CRC check") from exc
            raise CorruptFileError(f"Damaged entry {info.filename!r}: {exc}") from exc
        except zlib.error as exc:
            # A wrong ZipCrypto password that happens to pass the one-byte check
            # yields plausible-looking bytes that are not a valid deflate stream.
            # For an entry that was never encrypted, the same error means damage.
            if _is_encrypted(info):
                raise _zipcrypto_ambiguity(info, f"did not decompress ({exc})") from exc
            raise CorruptFileError(f"Damaged entry {info.filename!r}: {exc}") from exc

        digests.append(f"{info.filename}:{digest.hexdigest()}:{written}")
        return written

    # ------------------------------------------------------------ assurance
    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:
        digests: list[str] = []
        total = 0
        try:
            with zipfile.ZipFile(output) as zf:
                infos = zf.infolist()
                for info in infos:
                    if _is_encrypted(info):
                        raise VerificationError(
                            f"The written archive still has an encrypted entry "
                            f"({info.filename!r}). The output has been discarded."
                        )
                    if info.is_dir():
                        digests.append(f"{info.filename}:<dir>")
                        continue
                    digest = hashlib.sha256()
                    written = 0
                    with zf.open(info, "r") as src:
                        while True:
                            chunk = src.read(_CHUNK)
                            if not chunk:
                                break
                            written += len(chunk)
                            digest.update(chunk)
                    total += written
                    digests.append(f"{info.filename}:{digest.hexdigest()}:{written}")
        except zipfile.BadZipFile as exc:
            raise VerificationError(
                f"The written archive is not a readable ZIP: {exc}. The output has been discarded."
            ) from exc

        actual = {
            "entries": str(len(infos)),
            "content_digest": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
            "total_bytes": str(total),
        }
        for key in ("entries", "content_digest", "total_bytes"):
            if evidence.expectations.get(key) != actual[key]:
                raise VerificationError(
                    f"Output verification failed: {key} changed during decryption "
                    f"(expected {evidence.expectations.get(key)!r}, got {actual[key]!r}). "
                    "The output has been discarded.",
                    remediation="Please report this with the archive type and tool version.",
                )
        return {
            "encrypted": "false",
            "entries": actual["entries"],
            "bytes": actual["total_bytes"],
            "content_digest": actual["content_digest"][:16],
        }
