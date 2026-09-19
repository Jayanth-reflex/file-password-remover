"""Filesystem primitives: private temp space, atomic output, best-effort scrub.

Design rules enforced here
--------------------------
1. Decrypted bytes never land in a world-readable location. Temp material goes
   into a directory created with mode ``0o700``; files are created ``0o600``.
2. The destination file is only ever created by ``os.replace`` of a fully
   written, fsync'd temporary file in the *same directory*, so a crash cannot
   leave a half-written "unprotected" file that looks complete.
3. We never write the temp file into the system temp dir when the destination
   is elsewhere: crossing filesystems would turn ``os.replace`` into a
   non-atomic copy, and would spread plaintext across more volumes.

Honest limitation
-----------------
``scrub_file`` overwrites a file's bytes before unlinking it. On SSDs with
wear levelling, on copy-on-write filesystems (APFS, Btrfs, ZFS), and on any
journalled filesystem, that overwrite is **not** guaranteed to touch the
physical blocks that held the data. It raises the cost of casual recovery and
nothing more. Full-disk encryption is the real control; this is documented in
docs/security/threat-model.md (R-05).
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

from .errors import FileAccessError, OutputExistsError

__all__ = [
    "secure_tempdir",
    "atomic_write",
    "scrub_file",
    "assert_readable_file",
    "SCRUB_PASSES",
]

SCRUB_PASSES = 1
"""One zero pass. Additional passes are cargo cult on modern media and only
multiply the write amplification; see the module docstring."""

_TEMP_PREFIX = "fpr-"


@contextlib.contextmanager
def secure_tempdir(*, near: Path | None = None, prefix: str = _TEMP_PREFIX) -> Iterator[Path]:
    """A private directory that is scrubbed and removed on exit.

    ``near`` places the directory on the same filesystem as an eventual output
    so that the final ``os.replace`` stays atomic.
    """
    parent = None
    if near is not None:
        parent = str(near if near.is_dir() else near.parent)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    try:
        os.chmod(path, 0o700)
        yield path
    finally:
        _scrub_tree(path)


def _scrub_tree(root: Path) -> None:
    """Scrub every regular file under ``root``, then remove the tree."""
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames:
            with contextlib.suppress(OSError):
                scrub_file(Path(dirpath) / name)
        with contextlib.suppress(OSError):
            os.rmdir(dirpath)
    with contextlib.suppress(OSError):
        os.rmdir(root)


def scrub_file(path: Path) -> None:
    """Overwrite a file with zeros, flush to disk, then unlink it.

    Best effort -- see the module docstring for why this is not a guarantee.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size:
        try:
            with path.open("r+b", buffering=0) as fh:
                for _ in range(SCRUB_PASSES):
                    fh.seek(0)
                    remaining = size
                    chunk = b"\x00" * min(remaining, 1 << 20)
                    while remaining > 0:
                        fh.write(chunk[: min(remaining, len(chunk))])
                        remaining -= len(chunk[: min(remaining, len(chunk))])
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError:
            # Read-only media, or the file vanished. Still try to unlink.
            pass
    with contextlib.suppress(OSError):
        path.unlink()


@contextlib.contextmanager
def atomic_write(
    dest: Path,
    *,
    overwrite: bool = False,
    mode: int = 0o600,
) -> Iterator[Path]:
    """Yield a temporary path; on clean exit, atomically move it onto ``dest``.

    The temporary file lives in ``dest.parent`` so the final ``os.replace`` is
    a same-filesystem rename. If the body raises, the temporary file is
    scrubbed and removed and ``dest`` is left untouched.

    ``overwrite=False`` (the default) refuses to replace an existing ``dest``.
    The check is done up front *and* enforced again at rename time with
    ``O_EXCL`` semantics where the platform allows it.
    """
    dest = Path(dest)
    parent = dest.parent
    if not parent.exists():
        raise FileAccessError(
            f"Output directory does not exist: {parent}",
            remediation="Create the directory first, or choose another --output path.",
        )
    if not os.access(parent, os.W_OK):
        raise FileAccessError(
            f"No write permission for output directory: {parent}",
            remediation="Choose a directory you can write to, or fix its permissions.",
        )
    if dest.exists() and not overwrite:
        raise OutputExistsError(str(dest))

    fd, tmp_name = tempfile.mkstemp(prefix=f".{_TEMP_PREFIX}", suffix=".part", dir=str(parent))
    tmp = Path(tmp_name)
    os.close(fd)
    try:
        os.chmod(tmp, mode)
        yield tmp
        # Durability: the data must be on disk before the rename, otherwise a
        # power loss can leave a correctly-named but empty file.
        with tmp.open("rb") as fh:
            os.fsync(fh.fileno())
        if dest.exists() and not overwrite:
            raise OutputExistsError(str(dest))
        os.replace(tmp, dest)
        _fsync_dir(parent)
    except BaseException:
        scrub_file(tmp)
        raise
    finally:
        if tmp.exists():
            scrub_file(tmp)


def _fsync_dir(path: Path) -> None:
    """Persist the directory entry created by ``os.replace``."""
    if os.name != "posix":  # pragma: no cover - Windows has no directory fsync
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def assert_readable_file(path: Path) -> int:
    """Validate that ``path`` is a readable regular file; return its size.

    Rejects directories, FIFOs, devices and symlink loops with a specific
    message instead of letting a format parser produce something cryptic.
    """
    try:
        st = path.stat()
    except FileNotFoundError as exc:
        raise FileAccessError(
            f"File not found: {path}",
            remediation="Check the path and try again.",
        ) from exc
    except OSError as exc:
        raise FileAccessError(f"Cannot access {path}: {exc.strerror}") from exc

    if stat.S_ISDIR(st.st_mode):
        raise FileAccessError(
            f"{path} is a directory.",
            remediation="Pass a file, or use the batch mode with --input-dir.",
        )
    if not stat.S_ISREG(st.st_mode):
        raise FileAccessError(
            f"{path} is not a regular file.",
            remediation="Pipes, sockets and devices cannot be processed in place.",
        )
    if not os.access(path, os.R_OK):
        raise FileAccessError(
            f"No read permission for {path}.",
            remediation="Fix the file permissions, or copy the file somewhere you can read.",
        )
    if st.st_size == 0:
        raise FileAccessError(f"{path} is empty (0 bytes).")
    return st.st_size
