"""Error hierarchy and process exit codes.

Every user-visible failure in File Password Remover is one of these exceptions.
Each carries a stable ``exit_code`` so that scripts can branch on *why* a run
failed without parsing text, and a ``remediation`` string so that the CLI and
the GUI can show the same actionable advice.

Error messages never contain the password, and never contain file *contents*.
They may contain the file path, because the user supplied it.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "ExitCode",
    "FprError",
    "UsageError",
    "IncorrectPasswordError",
    "UnsupportedFormatError",
    "CorruptFileError",
    "NotProtectedError",
    "OutputExistsError",
    "FileAccessError",
    "VerificationError",
    "PolicyRefusedError",
    "DependencyMissingError",
    "PartialBatchFailure",
]


class ExitCode(IntEnum):
    """Process exit codes. These are part of the CLI's public contract."""

    OK = 0
    UNEXPECTED = 1
    USAGE = 2
    WRONG_PASSWORD = 3
    UNSUPPORTED_FORMAT = 4
    CORRUPT_FILE = 5
    NOT_PROTECTED = 6
    OUTPUT_EXISTS = 7
    IO_ERROR = 8
    VERIFICATION_FAILED = 9
    POLICY_REFUSED = 10
    DEPENDENCY_MISSING = 11
    PARTIAL_FAILURE = 12
    INTERRUPTED = 130


class FprError(Exception):
    """Base class for all expected failures.

    ``exit_code`` is a class attribute so that ``except FprError as e:
    sys.exit(e.exit_code)`` works for every subclass.
    """

    exit_code: ExitCode = ExitCode.UNEXPECTED

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation

    def __str__(self) -> str:
        return self.message


class UsageError(FprError):
    """The command line or API call itself was wrong."""

    exit_code = ExitCode.USAGE


class IncorrectPasswordError(FprError):
    """The supplied password did not match the file.

    Raised only after the format handler has positively determined that the
    password is wrong -- never as a catch-all for other decryption failures,
    because that would make a corrupt file look like a typo.
    """

    exit_code = ExitCode.WRONG_PASSWORD

    def __init__(
        self,
        message: str = "Incorrect password for this file.",
        *,
        remediation: str
        | None = "Check the password (including keyboard layout and caps lock) and try again.",
    ) -> None:
        super().__init__(message, remediation=remediation)


class UnsupportedFormatError(FprError):
    """The file type, or its particular protection scheme, is out of scope."""

    exit_code = ExitCode.UNSUPPORTED_FORMAT


class CorruptFileError(FprError):
    """The file is structurally damaged or truncated."""

    exit_code = ExitCode.CORRUPT_FILE


class NotProtectedError(FprError):
    """There is nothing to remove: the file carries no protection."""

    exit_code = ExitCode.NOT_PROTECTED


class OutputExistsError(FprError):
    """Refusing to clobber an existing file."""

    exit_code = ExitCode.OUTPUT_EXISTS

    def __init__(self, path: str) -> None:
        super().__init__(
            f"Output file already exists: {path}",
            remediation="Choose another --output path, or pass --overwrite to replace it.",
        )


class FileAccessError(FprError):
    """Could not read the input or write the output (permissions, disk, ...)."""

    exit_code = ExitCode.IO_ERROR


class VerificationError(FprError):
    """The output was produced but failed post-write verification.

    When this is raised the engine has already deleted the unverified output:
    a file that we cannot prove is both readable and unprotected must never be
    left on disk under a name that implies success.
    """

    exit_code = ExitCode.VERIFICATION_FAILED


class PolicyRefusedError(FprError):
    """The operation was refused on policy grounds, not technical grounds.

    This is what the tool raises when completing the request would amount to
    bypassing protection rather than removing it with the owner's password.
    """

    exit_code = ExitCode.POLICY_REFUSED


class DependencyMissingError(FprError):
    """An optional, separately installed component is required for this format."""

    exit_code = ExitCode.DEPENDENCY_MISSING


class PartialBatchFailure(FprError):
    """Some items in a batch succeeded and some did not."""

    exit_code = ExitCode.PARTIAL_FAILURE
