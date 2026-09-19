"""File Password Remover -- remove password protection from files you own.

Everything happens on the machine it runs on. There is no network code in this
package, no telemetry, and no cloud service; ``fpr`` only ever opens the files
you point it at.

Public API::

    from fpr import inspect, remove, RemovalOptions, Secret

    detection = inspect(Path("report.pdf"))       # no password needed
    with Secret.from_file("pw.txt") as pw:
        result = remove(Path("report.pdf"), pw)   # writes report-unprotected.pdf
"""

from __future__ import annotations

from .engine import DEFAULT_SUFFIX, RemovalOptions, inspect, plan_output_path, remove
from .errors import ExitCode, FprError
from .secret import Secret
from .types import Detection, FormatId, Protection, Removability, RemovalResult

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "inspect",
    "remove",
    "plan_output_path",
    "RemovalOptions",
    "DEFAULT_SUFFIX",
    "Secret",
    "Detection",
    "RemovalResult",
    "Protection",
    "Removability",
    "FormatId",
    "FprError",
    "ExitCode",
]
