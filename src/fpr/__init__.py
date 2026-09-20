"""File Password Remover -- remove password protection from files you own.

Everything happens on the machine it runs on. There is no network code in this
package, no telemetry, and no cloud service; ``fpr`` only ever opens the files
you point it at.

Public API::

    from fpr import inspect, remove, protect, RemovalOptions, Secret

    detection = inspect(Path("report.pdf"))       # no password needed
    with Secret.from_file("pw.txt") as pw:
        result = remove(Path("report.pdf"), pw)   # writes report-unprotected.pdf

    from fpr import passwords
    secret = passwords.generate()                 # the only copy that will exist
    protect(Path("notes.pdf"), secret)            # writes notes-protected.pdf
"""

from __future__ import annotations

from . import passwords
from .engine import (
    DEFAULT_SUFFIX,
    PROTECTED_SUFFIX,
    ProtectOptions,
    RemovalOptions,
    inspect,
    plan_output_path,
    plan_protected_path,
    protect,
    remove,
)
from .errors import ExitCode, FprError
from .secret import Secret
from .types import (
    Detection,
    FormatId,
    Protection,
    ProtectResult,
    Removability,
    RemovalResult,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "inspect",
    "remove",
    "protect",
    "passwords",
    "plan_output_path",
    "plan_protected_path",
    "RemovalOptions",
    "ProtectOptions",
    "DEFAULT_SUFFIX",
    "PROTECTED_SUFFIX",
    "Secret",
    "Detection",
    "RemovalResult",
    "ProtectResult",
    "Protection",
    "Removability",
    "FormatId",
    "FprError",
    "ExitCode",
]
