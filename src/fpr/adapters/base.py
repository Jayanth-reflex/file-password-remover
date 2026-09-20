"""The contract every format adapter implements.

An adapter is responsible for one container family. It must be able to answer
three questions, and it must answer them without ever guessing a password:

``sniff``    -- "are these bytes mine?"                    (no password)
``detect``   -- "what protection is on this file?"          (no password)
``remove``   -- "decrypt with this password and write it"   (password required)
``verify``   -- "prove the file I just wrote is readable and unprotected"

The split matters. ``detect`` is what the CLI's ``inspect`` command and the
GUI's drop target call, so a user can learn what they are holding before they
type a secret. ``verify`` is what makes the success message truthful: the
engine only reports success after the adapter has re-opened the output and
confirmed both that it is no longer protected and that the content it can
cheaply count still matches the input.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import UnsupportedFormatError
from ..secret import Secret
from ..types import Detection, FormatId, Protection

__all__ = ["Adapter", "AdapterOptions", "RemovalEvidence", "HEAD_BYTES"]

HEAD_BYTES = 512
"""How many leading bytes the registry reads once and hands to every ``sniff``."""


@dataclass(frozen=True, slots=True)
class AdapterOptions:
    """Per-run switches that change what an adapter is permitted to do."""

    allow_restriction_removal: bool = False
    """Clear owner/permission flags on a file whose content is *not* encrypted.

    Off by default. Even when on, the adapter must still have validated the
    supplied password as the **owner** password: see :mod:`fpr.policy`.
    """

    experimental: bool = False
    """Enable adapters/branches that have no automated fixture coverage."""

    preserve_timestamps: bool = True
    """Copy mtime/atime from the source to the output where the format allows."""


@dataclass(slots=True)
class ProtectEvidence:
    """What an adapter did while adding protection, for the verify step."""

    protection: Protection
    algorithm: str | None = None
    warnings: tuple[str, ...] = ()
    #: Whatever the adapter needs to prove the content survived, e.g. a page
    #: count or a map of member digests taken from the source before writing.
    expected: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class RemovalEvidence:
    """Facts captured while the decrypted input was open.

    ``expectations`` is the material ``verify`` compares the written output
    against. Adapters put cheap, high-signal invariants in it -- page counts,
    entry names, CRCs, part lists -- not full content hashes, because the
    output bytes legitimately differ from the input bytes after decryption.
    """

    protection: Protection
    algorithm: str | None = None
    expectations: dict[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


class Adapter(abc.ABC):
    """Base class for format adapters."""

    format_id: FormatId
    format_name: str
    extensions: tuple[str, ...] = ()

    # ------------------------------------------------------------- identity
    @classmethod
    @abc.abstractmethod
    def sniff(cls, head: bytes, path: Path) -> bool:
        """Return True if this adapter owns the file.

        Implementations must decide from ``head`` (and, where a container is
        ambiguous, a cheap structural peek at ``path``) -- never from the file
        extension alone, because renaming a file must not change behaviour.
        """

    # ------------------------------------------------------------ inspection
    @abc.abstractmethod
    def detect(self, path: Path) -> Detection:
        """Describe the protection on ``path`` without a password.

        Must not raise for a merely-unsupported protection scheme: return a
        :class:`~fpr.types.Detection` that says so. Raise only for I/O errors
        and genuinely corrupt containers.
        """

    # ---------------------------------------------------------------- action
    @abc.abstractmethod
    def remove(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> RemovalEvidence:
        """Write an unprotected copy of ``source`` to ``destination``.

        ``destination`` is a private temporary file supplied by the engine;
        the engine performs the atomic rename. Implementations must raise
        :class:`~fpr.errors.IncorrectPasswordError` **only** when they have
        positively established that the password is wrong.
        """

    @abc.abstractmethod
    def verify(self, output: Path, evidence: RemovalEvidence) -> dict[str, str]:
        """Re-open ``output`` and prove it is readable and unprotected.

        Returns a dict of human-readable proof for the report. Raises
        :class:`~fpr.errors.VerificationError` if anything fails to line up.
        """

    # ------------------------------------------------------------- utilities
    def protect(
        self,
        source: Path,
        destination: Path,
        secret: Secret,
        options: AdapterOptions,
    ) -> ProtectEvidence:
        """Write ``source`` to ``destination`` encrypted with ``secret``.

        Optional: adapters that cannot add protection inherit this refusal
        rather than pretending. Saying so plainly is the point -- a tool that
        silently wrote an unencrypted copy here would be dangerous.
        """
        raise UnsupportedFormatError(
            f"Adding protection to {self.format_id.value.upper()} files is not supported yet.",
            remediation="This tool can remove protection from this format, but not add it. "
            "PDF and ZIP can both be protected.",
        )

    def verify_protected(
        self, output: Path, secret: Secret, evidence: ProtectEvidence
    ) -> dict[str, str]:
        """Re-open ``output`` with ``secret`` and prove the content survived.

        Mirrors :meth:`verify`. Adapters that implement :meth:`protect` must
        implement this too: writing a file nobody has opened is not a success.
        """
        raise UnsupportedFormatError(
            f"Adding protection to {self.format_id.value.upper()} files is not supported yet."
        )

    def default_output_name(self, source: Path, suffix: str = "-unprotected") -> Path:
        """``report.pdf`` -> ``report-unprotected.pdf``."""
        return source.with_name(f"{source.stem}{suffix}{source.suffix}")
