"""In-memory handling of the user's password.

What this module can honestly promise
-------------------------------------
* The password is never an attribute of any object that reaches ``repr()``,
  ``str()``, ``%``/f-string formatting, ``pickle``, ``copy``, or a traceback
  frame's local-variable dump under a name that a logger would print.
* The mutable buffer we own is overwritten with zeros as soon as the operation
  finishes, and again at interpreter shutdown via ``weakref.finalize``.
* The password is never accepted on ``argv`` (it would be world-readable in
  ``ps``) -- see :mod:`fpr.cli.password_input`.

What it cannot promise -- and we say so in the docs rather than implying
otherwise
------------------------------------------------------------------------
* CPython ``str`` objects are immutable and interned in ways we do not control.
  Every third-party decryption API we call (``pikepdf``, ``msoffcrypto``,
  ``pyzipper``) takes ``str`` or ``bytes``, so at the moment of the call a
  copy exists that we cannot wipe. :meth:`Secret.expose` keeps the lifetime of
  that copy as short as the API allows and drops the only reference we hold.
* The OS may page the buffer to swap. We do not call ``mlock``: doing so
  needs elevated privileges on some platforms and would give a false sense of
  security where it silently fails. This is recorded as an accepted risk in
  docs/security/threat-model.md (R-07).
"""

from __future__ import annotations

import os
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

__all__ = ["Secret", "SecretError"]

MAX_PASSWORD_BYTES = 4096
"""Upper bound on a password read from a file/fd. Anything longer is a mistake
(usually a file that is not a password file) and is rejected rather than hashed."""


class SecretError(ValueError):
    """The password material could not be read, or was empty/oversized."""


def _wipe(buf: bytearray) -> None:
    """Overwrite a bytearray in place. Best effort; see module docstring."""
    n = len(buf)
    if n:
        buf[:] = b"\x00" * n
    del buf[:]


class Secret:
    """A password held as a mutable buffer that we can zero out.

    Use it as a context manager so the buffer is wiped deterministically::

        with Secret.from_text("hunter2") as pw:
            engine.remove(path, pw)
        # pw is now empty and unusable
    """

    __slots__ = ("_buf", "_closed", "_finalizer", "__weakref__")

    def __init__(self, material: bytes | bytearray) -> None:
        if not material:
            raise SecretError("The password is empty.")
        if len(material) > MAX_PASSWORD_BYTES:
            raise SecretError(
                f"Password material is {len(material)} bytes, which exceeds the "
                f"{MAX_PASSWORD_BYTES}-byte limit. Is this really a password file?"
            )
        self._buf = bytearray(material)
        self._closed = False
        self._finalizer = weakref.finalize(self, _wipe, self._buf)

    # ---------------------------------------------------------- constructors
    @classmethod
    def from_text(cls, text: str) -> Secret:
        """Build from a ``str``.

        The caller's ``str`` cannot be wiped; prefer :meth:`from_bytes`,
        :meth:`from_file` or :meth:`from_fd` on any path where we control the
        source. This exists for the GUI, whose toolkit hands us ``str``.
        """
        return cls(text.encode("utf-8"))

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> Secret:
        return cls(raw)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Secret:
        """Read a password from a file. A single trailing newline is stripped."""
        p = Path(path)
        try:
            st = p.stat()
        except OSError as exc:  # pragma: no cover - surfaced verbatim by callers
            raise SecretError(f"Cannot read password file: {exc.strerror}") from exc
        if st.st_size > MAX_PASSWORD_BYTES:
            raise SecretError(
                f"Password file is {st.st_size} bytes, over the {MAX_PASSWORD_BYTES}-byte limit."
            )
        if os.name == "posix" and st.st_mode & 0o077:
            # Not fatal: the user may knowingly use a shared file. Warn loudly
            # at the CLI layer instead of silently accepting it.
            pass
        raw = bytearray(p.read_bytes())
        try:
            return cls(_strip_one_newline(raw))
        finally:
            _wipe(raw)

    @classmethod
    def from_fd(cls, fd: int) -> Secret:
        """Read a password from an already-open file descriptor.

        This is the recommended non-interactive path: the parent process writes
        the password into a pipe, so it never appears in ``argv``, in the
        environment, or on disk.
        """
        chunks = bytearray()
        while len(chunks) <= MAX_PASSWORD_BYTES:
            block = os.read(fd, 4096)
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > MAX_PASSWORD_BYTES:
            _wipe(chunks)
            raise SecretError(f"Password on fd {fd} exceeds {MAX_PASSWORD_BYTES} bytes.")
        try:
            return cls(_strip_one_newline(chunks))
        finally:
            _wipe(chunks)

    # ------------------------------------------------------------- lifecycle
    def close(self) -> None:
        """Wipe the buffer. Idempotent."""
        if not self._closed:
            self._finalizer()
            self._closed = True

    def __enter__(self) -> Secret:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        return len(self._buf)

    # ---------------------------------------------------------------- access
    @contextmanager
    def expose(self) -> Iterator[str]:
        """Yield the password as ``str`` for the shortest possible window.

        Only decryption back-ends should call this, and only inside the call
        that needs it. The yielded ``str`` must not be stored.
        """
        self._check_open()
        text = self._buf.decode("utf-8", errors="surrogateescape")
        try:
            yield text
        finally:
            del text

    @contextmanager
    def expose_bytes(self) -> Iterator[bytes]:
        """Yield the raw password bytes (for APIs that want ``bytes``)."""
        self._check_open()
        raw = bytes(self._buf)
        try:
            yield raw
        finally:
            del raw

    def _check_open(self) -> None:
        if self._closed:
            raise SecretError("This Secret has already been wiped.")

    # ----------------------------------------------------- leak-proofing ---
    # Everything below exists so that an accidental log/format/serialise of a
    # Secret produces a placeholder instead of the password.
    def __repr__(self) -> str:
        state = "wiped" if self._closed else f"{len(self._buf)} bytes"
        return f"<Secret {state}>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)

    def __bytes__(self) -> NoReturn:
        raise SecretError("Refusing implicit bytes() of a Secret; use expose_bytes().")

    def __reduce__(self) -> NoReturn:
        raise SecretError("Secret objects cannot be pickled or copied.")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise SecretError("Secret objects cannot be pickled or copied.")

    def __copy__(self) -> NoReturn:
        raise SecretError("Secret objects cannot be pickled or copied.")

    def __eq__(self, other: object) -> bool:
        # Comparing secrets is not a use case here, and a naive __eq__ invites
        # timing oracles. Identity only.
        return self is other

    def __hash__(self) -> int:
        return id(self)


def _strip_one_newline(buf: bytearray) -> bytes:
    """Strip at most one trailing ``\\n`` or ``\\r\\n``.

    Exactly one, because a password may legitimately end in whitespace and
    ``.strip()`` would silently corrupt it.
    """
    end = len(buf)
    if end and buf[end - 1] == 0x0A:
        end -= 1
        if end and buf[end - 1] == 0x0D:
            end -= 1
    return bytes(buf[:end])
