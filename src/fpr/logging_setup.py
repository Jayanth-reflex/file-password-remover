"""Logging configuration with a redaction filter.

The tool does not log passwords: no code path passes secret material to a
logger. This filter is the belt to that braces -- if a future change ever does,
the record is scrubbed before a handler can write it to a file, a terminal, a
crash reporter or a support bundle.

There is no telemetry in this project. Nothing is sent anywhere.
"""

from __future__ import annotations

import logging
import re
import sys

__all__ = ["configure", "RedactionFilter", "REDACTED"]

REDACTED = "[redacted]"

# Patterns that must never reach a handler. Conservative on purpose: a false
# positive costs a slightly less readable log line, a false negative leaks.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|passwd|passphrase|secret|pwd)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)--password[= ]\S+"),
    re.compile(r"(?i)\bpassword\s+is\s+\S+"),
)


class RedactionFilter(logging.Filter):
    """Scrub anything that looks like credential material from a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging break the run
            return True
        scrubbed = message
        for pattern in _PATTERNS:
            scrubbed = pattern.sub(REDACTED, scrubbed)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


def configure(verbosity: int = 0, *, stream: object | None = None) -> None:
    """Set up root logging. ``verbosity`` 0 = warnings, 1 = info, 2+ = debug."""
    level = {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)
    handler = logging.StreamHandler(stream or sys.stderr)  # type: ignore[arg-type]
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    # Third-party debug logs can be extremely chatty and may echo file content.
    for noisy in ("pikepdf", "msoffcrypto", "PIL"):
        logging.getLogger(noisy).setLevel(max(level, logging.INFO))
