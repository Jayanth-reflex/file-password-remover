"""7-Zip archives with AES-256 encryption (optional extra).

Availability
------------
This adapter needs ``py7zr``, which is LGPL-2.1-or-later. The default
installation and the signed binaries stay permissively licensed, so ``py7zr``
is an opt-in extra::

    pip install "file-password-remover[sevenzip]"

Importing this module raises ``ImportError`` when the extra is absent; the
registry treats that as "adapter not available". See
docs/adr/0006-optional-lgpl-sevenzip-extra.md.

How it works
------------
py7zr (1.x) has no in-memory read API, so the archive is expanded into a
private ``0700`` directory on the destination's own filesystem and repacked
from there. The temp tree is scrubbed and removed whether the run succeeds or
fails.

Path safety: entry names are checked *before* extraction. An archive
containing an absolute path or a ``..`` segment is refused outright rather than
being allowed to write outside the extraction directory.

Header encryption: 7-Zip can encrypt the archive header, hiding even the file
names. Detection reports that instead of pretending the archive is empty.
"""

from __future__ import annotations

import functools
import hashlib
import weakref
from pathlib import Path, PurePosixPath
from typing import Any

import py7zr  # noqa: F401  -- import failure here is the availability signal
import py7zr.compressor

from ..errors import (
    CorruptFileError,
    IncorrectPasswordError,
    UnsupportedFormatError,
    VerificationError,
)
from ..secret import Secret
from ..securefs import secure_tempdir
from ..types import Detection, FormatId, Protection, Removability
from .base import Adapter, AdapterOptions, RemovalEvidence

__all__ = ["SevenZipAdapter"]

SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
_CHUNK = 1 << 20


class _NoProgressError(Exception):
    """py7zr's decompressor can make no further progress (see below)."""


# Consecutive calls that return nothing without reading anything. One could in
# principle be a legitimate pause; several in a row cannot be.
_STALL_LIMIT = 3


def _guard_against_no_progress() -> None:
    """Make py7zr fail instead of looping forever on a stalled stream.

    py7zr 1.1.3 extracts with ``while out_remaining > 0: tmp =
    decompressor.decompress(fp, ...)`` and never checks for progress. A wrong
    AES key occasionally decrypts to bytes the LZMA decoder accepts without
    complaint until the packed input is used up; from then on every call reads
    nothing, returns nothing, and the loop spins for ever. That is how
    `fpr remove` with a wrong password hung a CI job
    (docs/adr/0012-guard-py7zr-against-no-progress.md).

    The wrapper counts calls that neither produced output nor moved the
    archive's file position -- judged by ``fp.tell()`` alone, not by py7zr's
    private counters -- and raises after a few in a row. In any extraction that
    can finish, every call does one or the other, so behaviour only changes in
    the state that could only have hung. Installed once; idempotent.
    """
    cls = getattr(py7zr.compressor, "SevenZipDecompressor", None)
    if cls is None or not hasattr(cls, "decompress"):
        # A py7zr that restructured this has also changed the loop being
        # guarded. Extraction still works; test_the_no_progress_guard_is_installed
        # fails, which is the prompt to re-examine the ADR.
        return
    if getattr(cls.decompress, "_fpr_guarded", False):
        return
    original = cls.decompress
    idle: weakref.WeakKeyDictionary[Any, int] = weakref.WeakKeyDictionary()

    @functools.wraps(original)
    def decompress(self: Any, fp: Any, max_length: int = -1) -> bytes:
        before = fp.tell()
        data: bytes = original(self, fp, max_length)
        if data or fp.tell() != before:
            idle[self] = 0
            return data
        idle[self] = idle.get(self, 0) + 1
        if idle[self] >= _STALL_LIMIT:
            raise _NoProgressError("the compressed stream ended before its declared size")
        return data

    decompress._fpr_guarded = True  # type: ignore[attr-defined]
    cls.decompress = decompress


_guard_against_no_progress()


def _unsafe(name: str) -> bool:
    pure = PurePosixPath(name.replace("\\", "/"))
    return pure.is_absolute() or ".." in pure.parts


class SevenZipAdapter(Adapter):
    format_id = FormatId.SEVENZIP
    format_name = "7-Zip archive"
    extensions = (".7z",)

    @classmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        return head.startswith(SEVENZIP_MAGIC)

    def detect(self, path: Path) -> Detection:

        try:
            with py7zr.SevenZipFile(path, mode="r") as archive:
                encrypted = bool(archive.needs_password())
                names = archive.getnames()
        except py7zr.PasswordRequired:
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.USER_PASSWORD,
                removability=Removability.REMOVABLE,
                algorithm="AES-256 with encrypted header",
                detail=(
                    "The archive header is encrypted, so even the entry names stay hidden "
                    "until the password is supplied."
                ),
            )
        except py7zr.Bad7zFile as exc:
            raise CorruptFileError(f"This file is not a readable 7-Zip archive: {exc}") from exc

        if not encrypted:
            return Detection(
                path=path,
                format_id=self.format_id,
                format_name=self.format_name,
                protection=Protection.NONE,
                removability=Removability.NOT_PROTECTED,
                detail=f"No encryption; {len(names)} entr(ies).",
            )
        return Detection(
            path=path,
            format_id=self.format_id,
            format_name=self.format_name,
            protection=Protection.USER_PASSWORD,
            removability=Removability.REMOVABLE,
            algorithm="AES-256",
            detail=f"{len(names)} entr(ies), contents encrypted with AES-256.",
        )

    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:

        with secure_tempdir(near=destination) as workdir:
            with secret.expose() as password:
                try:
                    archive = py7zr.SevenZipFile(source, mode="r", password=password)
                except py7zr.PasswordRequired as exc:  # pragma: no cover
                    raise IncorrectPasswordError() from exc
                except py7zr.Bad7zFile as exc:
                    raise CorruptFileError(f"Unreadable 7-Zip archive: {exc}") from exc

                with archive:
                    if not archive.needs_password():
                        raise UnsupportedFormatError(
                            "This 7-Zip archive is not encrypted, so there is nothing to decrypt."
                        )
                    names = archive.getnames()
                    unsafe = [n for n in names if _unsafe(n)]
                    if unsafe:
                        raise UnsupportedFormatError(
                            f"Refusing to extract: {len(unsafe)} entr(ies) use an absolute path "
                            f"or '..' (first: {unsafe[0]!r}).",
                            remediation="This archive would write outside its own directory.",
                        )
                    try:
                        archive.extractall(path=str(workdir))
                    except (
                        py7zr.PasswordRequired,
                        py7zr.exceptions.CrcError,
                        # A wrong key can decode to an early end-of-stream
                        # marker; py7zr then raises EOFError on the next read.
                        EOFError,
                        _NoProgressError,
                    ) as exc:
                        raise IncorrectPasswordError(
                            "The archive did not decrypt with this password.",
                            remediation="Re-check the password; if it is definitely right, the "
                            "archive is damaged.",
                        ) from exc
                    except (py7zr.Bad7zFile, py7zr.UnsupportedCompressionMethodError) as exc:
                        raise CorruptFileError(f"Could not extract the archive: {exc}") from exc
                    except Exception as exc:  # noqa: BLE001
                        # py7zr surfaces a wrong password as a raw decompressor
                        # error (_lzma.LZMAError: Corrupt input data), which we
                        # must not report as file damage.
                        if "corrupt" in str(exc).lower() or "lzma" in type(exc).__module__.lower():
                            raise IncorrectPasswordError(
                                "The archive did not decrypt with this password.",
                                remediation="Re-check the password; if it is definitely right, "
                                "the archive is damaged.",
                            ) from exc
                        raise

            digests, total = _digest_tree(workdir)
            with py7zr.SevenZipFile(destination, mode="w") as out:
                for member in sorted(p for p in workdir.rglob("*") if p.is_file()):
                    out.write(member, arcname=str(member.relative_to(workdir)))

        return RemovalEvidence(
            protection=Protection.USER_PASSWORD,
            algorithm="AES-256",
            expectations={
                "entries": str(len(digests)),
                "content_digest": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
                "total_bytes": str(total),
            },
            warnings=(
                "7-Zip support is provided by py7zr (LGPL-2.1-or-later) and is not bundled in "
                "the released binaries.",
            ),
        )

    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:

        with secure_tempdir(near=output) as workdir:
            try:
                with py7zr.SevenZipFile(output, mode="r") as archive:
                    if archive.needs_password():
                        raise VerificationError(
                            "The written archive is still encrypted. The output has been discarded."
                        )
                    archive.extractall(path=str(workdir))
            except py7zr.Bad7zFile as exc:
                raise VerificationError(
                    f"The written archive is not readable: {exc}. The output has been discarded."
                ) from exc
            digests, total = _digest_tree(workdir)

        actual = {
            "entries": str(len(digests)),
            "content_digest": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
            "total_bytes": str(total),
        }
        for key in ("entries", "content_digest", "total_bytes"):
            if evidence.expectations.get(key) != actual[key]:
                raise VerificationError(
                    f"Output verification failed: {key} changed during decryption "
                    f"(expected {evidence.expectations.get(key)!r}, got {actual[key]!r}). "
                    "The output has been discarded."
                )
        return {
            "encrypted": "false",
            "entries": actual["entries"],
            "bytes": actual["total_bytes"],
            "content_digest": actual["content_digest"][:16],
        }


def _digest_tree(root: Path) -> tuple[list[str], int]:
    """Name + SHA-256 + size of every file under ``root``, in a stable order."""
    digests: list[str] = []
    total = 0
    for member in sorted(p for p in root.rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        size = 0
        with member.open("rb") as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
        rel = member.relative_to(root).as_posix()
        digests.append(f"{rel}:{digest.hexdigest()}:{size}")
        total += size
    return digests, total
