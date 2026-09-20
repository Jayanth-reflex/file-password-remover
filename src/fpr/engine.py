"""Orchestration: detect -> authorise -> decrypt -> verify -> publish.

The order is the whole point. Nothing is written where the user asked for it
until a separate read-back has proved the file is both openable and no longer
protected; if that proof fails, the output is scrubbed and an error is raised.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from . import policy, registry
from .adapters.base import AdapterOptions
from .errors import FileAccessError, FprError, PolicyRefusedError
from .secret import Secret
from .securefs import assert_readable_file, atomic_write, scrub_file
from .types import Detection, Protection, ProtectResult, RemovalResult

log = logging.getLogger(__name__)

__all__ = [
    "RemovalOptions",
    "ProtectOptions",
    "inspect",
    "remove",
    "protect",
    "plan_output_path",
    "plan_protected_path",
    "DEFAULT_SUFFIX",
    "PROTECTED_SUFFIX",
]

DEFAULT_SUFFIX = "-unprotected"
PROTECTED_SUFFIX = "-protected"


@dataclass(frozen=True, slots=True)
class RemovalOptions:
    """Everything the caller can vary for one removal."""

    output: Path | None = None
    output_dir: Path | None = None
    suffix: str = DEFAULT_SUFFIX
    overwrite: bool = False
    in_place: bool = False
    allow_restriction_removal: bool = False
    experimental: bool = False
    preserve_timestamps: bool = True

    def adapter_options(self) -> AdapterOptions:
        return AdapterOptions(
            allow_restriction_removal=self.allow_restriction_removal,
            experimental=self.experimental,
            preserve_timestamps=self.preserve_timestamps,
        )


@dataclass(frozen=True, slots=True)
class ProtectOptions:
    """Everything the caller can vary for one protect run.

    Deliberately has **no** ``in_place``. Removing protection in place is
    recoverable -- the password still exists. Adding it in place is not: if the
    only copy of a generated password is lost, the file is gone, and this tool
    refuses to crack it back open. So protection is always written to a new
    file and the original is left alone.
    """

    output: Path | None = None
    output_dir: Path | None = None
    suffix: str = PROTECTED_SUFFIX
    overwrite: bool = False
    preserve_timestamps: bool = True

    def adapter_options(self) -> AdapterOptions:
        return AdapterOptions(preserve_timestamps=self.preserve_timestamps)


def inspect(path: Path) -> Detection:
    """Identify a file and describe its protection. Never needs a password."""
    path = Path(path)
    assert_readable_file(path)
    return registry.detect(path)


def plan_output_path(source: Path, options: RemovalOptions) -> Path:
    """Where the unprotected copy will go, without creating anything."""
    if options.in_place:
        return source
    if options.output is not None:
        return options.output
    name = f"{source.stem}{options.suffix}{source.suffix}"
    directory = options.output_dir if options.output_dir is not None else source.parent
    return directory / name


def plan_protected_path(source: Path, options: ProtectOptions) -> Path:
    """Where the protected copy will go, without creating anything."""
    if options.output is not None:
        return options.output
    name = f"{source.stem}{options.suffix}{source.suffix}"
    directory = options.output_dir if options.output_dir is not None else source.parent
    return directory / name


def protect(source: Path, secret: Secret, options: ProtectOptions | None = None) -> ProtectResult:
    """Write a verified, password-protected copy of ``source``.

    The output is opened again *with the password* before this returns, so a
    success means the file has been proved to open and to still contain what it
    started with.
    """
    options = options or ProtectOptions()
    source = Path(source)
    size_in = assert_readable_file(source)

    detection = registry.detect(source)
    if detection.protection not in (Protection.NONE, Protection.UNKNOWN):
        raise PolicyRefusedError(
            f"{source.name} is already protected ({detection.protection.value}).",
            remediation="Remove the existing protection first if you want to change the "
            "password. Encrypting it again would leave two passwords to keep, and losing "
            "either one would be unrecoverable.",
        )

    adapter = registry.adapter_for(source)
    destination = plan_protected_path(source, options)

    if destination.resolve() == source.resolve():
        raise FileAccessError(
            "The output path is the same as the input file.",
            remediation="Protection is always written to a new file: if the password were "
            "lost there would be no way back. Choose a different --output.",
        )

    started = time.monotonic()
    log.debug("protecting: format=%s dest=%s", detection.format_id.value, destination)

    with atomic_write(destination, overwrite=options.overwrite) as tmp:
        try:
            evidence = adapter.protect(source, tmp, secret, options.adapter_options())
            proof = adapter.verify_protected(tmp, secret, evidence)
        except FprError:
            raise
        except Exception as exc:  # noqa: BLE001 - turn surprises into a clean failure
            log.debug("adapter raised", exc_info=True)
            raise FileAccessError(
                f"Unexpected failure while protecting {source.name}: {type(exc).__name__}: {exc}",
                remediation="Please report this with the file type and tool version.",
            ) from exc
        size_out = tmp.stat().st_size
        if options.preserve_timestamps:
            _copy_times(source, tmp)

    return ProtectResult(
        source=source,
        output=destination,
        format_id=detection.format_id,
        protection_applied=evidence.protection,
        algorithm=evidence.algorithm,
        bytes_in=size_in,
        bytes_out=size_out,
        duration_s=time.monotonic() - started,
        verification=proof,
        warnings=evidence.warnings,
    )


def remove(source: Path, secret: Secret, options: RemovalOptions | None = None) -> RemovalResult:
    """Write a verified, unprotected copy of ``source``.

    Raises a :class:`~fpr.errors.FprError` subclass for every expected failure;
    each one carries an exit code and a remediation hint.
    """
    options = options or RemovalOptions()
    source = Path(source)
    size_in = assert_readable_file(source)

    detection = registry.detect(source)
    policy.check(detection, allow_restriction_removal=options.allow_restriction_removal)

    adapter = registry.adapter_for(source)
    destination = plan_output_path(source, options)

    if destination.resolve() == source.resolve() and not options.in_place:
        raise FileAccessError(
            "The output path is the same as the input file.",
            remediation="Choose a different --output, or pass --in-place to replace the "
            "original deliberately.",
        )

    started = time.monotonic()
    log.debug("removing protection: format=%s dest=%s", detection.format_id.value, destination)

    # atomic_write hands us a private temp file next to the destination; the
    # rename only happens if this block completes without raising.
    with atomic_write(destination, overwrite=options.overwrite or options.in_place) as tmp:
        try:
            evidence = adapter.remove(source, tmp, secret, options.adapter_options())
            proof = adapter.verify(tmp, evidence)
        except FprError:
            raise
        except Exception as exc:  # noqa: BLE001 - turn surprises into a clean failure
            log.debug("adapter raised", exc_info=True)
            raise FileAccessError(
                f"Unexpected failure while processing {source.name}: {type(exc).__name__}: {exc}",
                remediation="Please report this with the file type and tool version.",
            ) from exc
        size_out = tmp.stat().st_size
        if options.preserve_timestamps:
            _copy_times(source, tmp)

    duration = time.monotonic() - started
    return RemovalResult(
        source=source,
        output=destination,
        format_id=detection.format_id,
        protection_removed=evidence.protection,
        algorithm=evidence.algorithm or detection.algorithm,
        bytes_in=size_in,
        bytes_out=size_out,
        duration_s=duration,
        verification=proof,
        warnings=evidence.warnings,
    )


def _copy_times(source: Path, target: Path) -> None:
    """Mirror the source's mtime/atime onto the output.

    Deliberately *not* the mode: the output of a decryption should start at the
    restrictive 0600 the temp file was created with, not inherit a source file
    that may be world-readable.
    """
    try:
        st = source.stat()
        os.utime(target, (st.st_atime, st.st_mtime))
    except OSError:  # pragma: no cover - non-fatal
        log.debug("could not preserve timestamps", exc_info=True)


def discard(path: Path) -> None:
    """Remove an output we are no longer willing to stand behind."""
    scrub_file(path)
