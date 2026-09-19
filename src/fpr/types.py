"""Value types shared by the engine, the adapters, the CLI and the GUI.

Nothing in this module imports an adapter, so it can be imported cheaply (the
CLI uses it for ``--list-formats`` without importing pikepdf).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

__all__ = [
    "Protection",
    "Removability",
    "FormatId",
    "Detection",
    "Outcome",
    "RemovalResult",
    "BatchReport",
]


class Protection(str, Enum):
    """What kind of protection a file carries.

    The distinction matters legally and technically:

    ``USER_PASSWORD``
        The bytes are encrypted. Without the password there is no content.
        Supplying the password and re-saving is decryption, not a bypass.
    ``OWNER_RESTRICTIONS``
        The content is readable by anyone (the "user password" is empty) but
        flags ask consumers to forbid printing/copying/editing. Clearing those
        flags *without* the owner password is a bypass, so this tool refuses
        to do it -- see :mod:`fpr.policy`.
    ``BOTH``
        Encrypted *and* carrying restriction flags.
    ``DRM``
        Rights management enforced by a third-party licence server or device
        key. Out of scope, permanently.
    ``UNKNOWN``
        Detected as protected, but the scheme is not one we understand.
    """

    NONE = "none"
    # These are enum labels describing a kind of protection, not credentials.
    USER_PASSWORD = "user-password"  # nosec B105
    OWNER_RESTRICTIONS = "owner-restrictions"
    BOTH = "user-password+owner-restrictions"
    DRM = "drm"
    UNKNOWN = "unknown"


class Removability(str, Enum):
    """Whether this tool will act on the detected protection."""

    REMOVABLE = "removable"
    """Removable once the correct password is supplied."""

    REMOVABLE_WITH_OWNER_PASSWORD = "removable-with-owner-password"  # nosec B105
    """Restriction-only file: needs the *owner* password, not any password."""

    REFUSED_BY_POLICY = "refused-by-policy"
    """Technically possible but would constitute a bypass. We will not do it."""

    UNSUPPORTED = "unsupported"
    """Not implemented, or not reliably implementable."""

    NOT_PROTECTED = "not-protected"


class FormatId(str, Enum):
    """Stable identifiers for the formats the tool knows about."""

    PDF = "pdf"
    OOXML = "ooxml"
    LEGACY_OFFICE = "legacy-office"
    ZIP = "zip"
    SEVENZIP = "7z"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Detection:
    """The result of inspecting a file *without* a password.

    Detection is deliberately password-free: the CLI's ``inspect`` command runs
    it so that a user can find out what they are holding before typing a
    secret, and so that batch runs can be planned offline.
    """

    path: Path
    format_id: FormatId
    format_name: str
    protection: Protection
    removability: Removability
    algorithm: str | None = None
    """Human-readable cipher description, e.g. ``"AES-256 (PDF 2.0, R6)"``."""

    detail: str = ""
    """One sentence a user can act on."""

    extension_mismatch: bool = False
    """True when the file's magic bytes disagree with its suffix."""

    @property
    def is_protected(self) -> bool:
        return self.protection not in (Protection.NONE,)

    @property
    def actionable(self) -> bool:
        return self.removability in (
            Removability.REMOVABLE,
            Removability.REMOVABLE_WITH_OWNER_PASSWORD,
        )


class Outcome(str, Enum):
    REMOVED = "removed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class RemovalResult:
    """The result of a single successful removal, after verification."""

    source: Path
    output: Path
    format_id: FormatId
    protection_removed: Protection
    algorithm: str | None
    bytes_in: int
    bytes_out: int
    duration_s: float
    verification: dict[str, str] = field(default_factory=dict)
    """Adapter-specific proof, e.g. ``{"pages": "12", "encrypted": "false"}``."""

    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BatchItemReport:
    source: Path
    outcome: Outcome
    output: Path | None = None
    error_code: str | None = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class BatchReport:
    items: tuple[BatchItemReport, ...]

    @property
    def removed(self) -> int:
        return sum(1 for i in self.items if i.outcome is Outcome.REMOVED)

    @property
    def failed(self) -> int:
        return sum(1 for i in self.items if i.outcome is Outcome.FAILED)

    @property
    def skipped(self) -> int:
        return sum(1 for i in self.items if i.outcome is Outcome.SKIPPED)
