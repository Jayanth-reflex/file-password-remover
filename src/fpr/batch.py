"""Batch processing.

Batch mode exists so that a folder of files protected with the *same* password
can be handled in one pass. It deliberately does not:

* try one file's password on another set of files -- the password is supplied
  once by the user and used only where they pointed it;
* stop at the first failure, which would leave a half-done directory with no
  record of what happened;
* report overall success when any item failed. A run with failures exits with
  ``ExitCode.PARTIAL_FAILURE`` (12) and prints a per-item table.

Files that are not protected, or whose format is unsupported, are *skipped*
rather than failed: in a mixed folder that is the useful behaviour, and the
report still names every one of them.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from .engine import RemovalOptions, remove
from .errors import FprError, NotProtectedError, UnsupportedFormatError
from .secret import Secret
from .types import BatchItemReport, BatchReport, Outcome

log = logging.getLogger(__name__)

__all__ = ["run_batch", "collect_inputs"]

ProgressHook = Callable[[int, int, Path], None]


def collect_inputs(
    paths: Sequence[Path],
    *,
    recursive: bool = False,
    patterns: Sequence[str] = ("*",),
) -> list[Path]:
    """Expand files and directories into a stable, de-duplicated file list."""
    found: list[Path] = []
    seen: set[Path] = set()
    for item in paths:
        if item.is_dir():
            globber = item.rglob if recursive else item.glob
            for pattern in patterns:
                for candidate in sorted(globber(pattern)):
                    if candidate.is_file():
                        _add(candidate, found, seen)
        else:
            _add(item, found, seen)
    return found


def _add(path: Path, found: list[Path], seen: set[Path]) -> None:
    resolved = path.resolve()
    if resolved not in seen:
        seen.add(resolved)
        found.append(path)


def run_batch(
    inputs: Iterable[Path],
    secret: Secret,
    options: RemovalOptions | None = None,
    *,
    on_progress: ProgressHook | None = None,
    stop_on_error: bool = False,
) -> BatchReport:
    """Process every input with the same password; never raise for one item."""
    items = list(inputs)
    reports: list[BatchItemReport] = []
    for index, path in enumerate(items, start=1):
        if on_progress:
            on_progress(index, len(items), path)
        try:
            result = remove(path, secret, options)
        except (NotProtectedError, UnsupportedFormatError) as exc:
            reports.append(
                BatchItemReport(
                    source=path,
                    outcome=Outcome.SKIPPED,
                    error_code=type(exc).__name__,
                    message=str(exc),
                )
            )
        except FprError as exc:
            reports.append(
                BatchItemReport(
                    source=path,
                    outcome=Outcome.FAILED,
                    error_code=type(exc).__name__,
                    message=str(exc),
                )
            )
            if stop_on_error:
                break
        else:
            reports.append(
                BatchItemReport(source=path, outcome=Outcome.REMOVED, output=result.output)
            )
    return BatchReport(items=tuple(reports))
