"""Rendering results for humans and for machines.

Two rules shape everything here:

* Success is only ever printed for a result that came back from the engine,
  which means it has already been verified by re-reading the written file. The
  renderer has no way to say "done" on its own.
* Colour and symbols degrade. When stdout is not a TTY, or ``NO_COLOR`` is set,
  or the terminal cannot encode the glyph, the output falls back to plain ASCII
  words -- which is also what screen readers and CI logs want.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, TextIO

from ..secret import Secret
from ..types import (
    BatchReport,
    Detection,
    Outcome,
    ProtectResult,
    RemovalResult,
)

__all__ = ["Renderer", "supports_colour", "human_size"]

_RESET = "\033[0m"
# "brass" is the one accent in the design system (docs/design/design-system.md).
# It needs a 256-colour terminal to look like metal; on an 8-colour terminal it
# degrades to plain yellow, which is the closest honest approximation.
_BRASS_256 = "\033[38;5;179m"
_BRASS_8 = "\033[33m"
_COLOURS = {
    "ok": "\033[32m",
    "warn": "\033[33m",
    "err": "\033[31m",
    "dim": "\033[2m",
    "brass": _BRASS_8,
}

# Shorter captions for the hallmark row, so it stays one line on an 80-column
# terminal. Only the caption is shortened -- the value is always printed exactly
# as the engine reported it, because the value is the evidence.
_MARK_CAPTIONS = {
    "content_digest": "digest",
    "content_scope": "scope",
    "docinfo_keys": "docinfo",
    "has_xmp": "xmp",
    "protection_removed": "removed",
}

# Captions are indented under the status glyph so the eye has one left edge.
_INDENT = "   "
_LABEL_WIDTH = 12


def supports_256_colour() -> bool:
    if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"}:
        return True
    return "256" in os.environ.get("TERM", "")


def supports_colour(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FPR_FORCE_COLOR") is not None:
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def human_size(n: int) -> str:
    step = 1024.0
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < step or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} TiB"  # pragma: no cover


def _caption(text: str) -> str:
    """Upper case, to match the hallmark captions."""
    return text.upper()


def _encodable(stream: TextIO, text: str) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class Renderer:
    """Writes either a readable report or one JSON object per run."""

    def __init__(self, stream: TextIO | None = None, *, as_json: bool = False, quiet: bool = False):
        self.stream = stream or sys.stdout
        self.as_json = as_json
        self.quiet = quiet
        self.colour = supports_colour(self.stream) and not as_json
        self.symbols = _encodable(self.stream, "✓ ✗ ⚠") and not as_json
        # Box drawing is a separate question from glyph support: a terminal can
        # manage ✓ and still mangle ─.
        self.rules = _encodable(self.stream, "─·→") and not as_json
        self.palette = dict(_COLOURS)
        if self.colour and supports_256_colour():
            self.palette["brass"] = _BRASS_256

    # ------------------------------------------------------------ primitives
    def _paint(self, text: str, kind: str) -> str:
        if not self.colour:
            return text
        return f"{self.palette.get(kind, '')}{text}{_RESET}"

    def _width(self) -> int:
        try:
            return max(40, min(shutil.get_terminal_size(fallback=(80, 24)).columns, 100))
        except OSError:  # pragma: no cover - no controlling terminal
            return 80

    def _rule(self, width: int) -> str:
        return ("─" if self.rules else "-") * width

    def _arrow(self) -> str:
        return "→" if self.rules else "->"

    def _dot(self) -> str:
        return "·" if self.rules else "-"

    def _field(self, label: str, value: str) -> None:
        """One label/value pair, on the shared left edge."""
        self.line(f"{_INDENT}{self._paint(label.ljust(_LABEL_WIDTH), 'dim')}{value}")

    def _hallmark(self, marks: dict[str, str]) -> None:
        """The verification evidence, as a row of struck marks.

        This is the signature element of the interface: a caption naming each
        property that was checked, with the value that came back underneath.
        Columns are sized to whichever of the two is wider so they always line
        up, and the row wraps into blocks rather than overflowing a narrow
        terminal.
        """
        if not marks:
            return
        available = self._width() - len(_INDENT)
        columns = [(_MARK_CAPTIONS.get(key, key).upper(), value) for key, value in marks.items()]

        block: list[tuple[str, str]] = []
        used = 0
        blocks: list[list[tuple[str, str]]] = []
        for caption, value in columns:
            span = max(len(caption), len(value)) + 3
            if block and used + span > available:
                blocks.append(block)
                block, used = [], 0
            block.append((caption, value))
            used += span
        if block:
            blocks.append(block)

        self.line()
        for group in blocks:
            widths = [max(len(caption), len(value)) for caption, value in group]
            caption_row = "  ".join(
                caption.ljust(width) for (caption, _), width in zip(group, widths, strict=True)
            )
            value_row = "  ".join(
                value.ljust(width) for (_, value), width in zip(group, widths, strict=True)
            )
            self.line(_INDENT + self._paint(caption_row.rstrip(), "brass"))
            self.line(_INDENT + value_row.rstrip())
        self.line(_INDENT + self._paint(self._rule(min(available, 46)), "dim"))

    def _mark(self, kind: str) -> str:
        if self.symbols:
            return {"ok": "✓", "err": "✗", "warn": "⚠"}[kind]
        return {"ok": "OK", "err": "FAIL", "warn": "WARN"}[kind]

    def line(self, text: str = "") -> None:
        if not self.quiet:
            print(text, file=self.stream)

    def json(self, payload: dict[str, Any]) -> None:
        print(json.dumps(payload, indent=2, default=_encode), file=self.stream)

    # -------------------------------------------------------------- reports
    def detection(self, detection: Detection) -> None:
        if self.as_json:
            self.json(_detection_payload(detection))
            return
        self.line(f"{detection.path.name}")
        self._field("format", f"{detection.format_name} ({detection.format_id.value})")
        self._field("protection", detection.protection.value)
        if detection.algorithm:
            self._field("algorithm", detection.algorithm)
        self._field("removable", detection.removability.value)
        if detection.extension_mismatch:
            self.line(
                f"{_INDENT}{self._paint(self._mark('warn'), 'warn')} "
                + self._paint("the file extension does not match its contents", "warn")
            )
        if detection.detail:
            self._field("note", detection.detail)
        self._field("path", str(detection.path))

    def result(self, result: RemovalResult) -> None:
        if self.as_json:
            self.json(_result_payload(result))
            return
        self.line(
            f"{self._paint(self._mark('ok'), 'ok')} "
            f"{self._paint('VERIFIED', 'ok')}  {result.output.name}"
        )
        self._field("removed", result.protection_removed.value)
        if result.algorithm:
            self._field("algorithm", result.algorithm)
        self._field(
            "size",
            f"{human_size(result.bytes_in)} {self._arrow()} {human_size(result.bytes_out)} "
            f"{self._dot()} {result.duration_s:.2f}s",
        )
        self._hallmark(dict(result.verification))
        self._field("saved to", str(result.output))
        self._field("original", f"{result.source} (unchanged)")
        for warning in result.warnings:
            self.line(
                f"{_INDENT}{self._paint(self._mark('warn'), 'warn')} {self._paint(warning, 'warn')}"
            )

    def protected(
        self,
        result: ProtectResult,
        *,
        generated: Secret | None = None,
        password_file: Path | None = None,
    ) -> None:
        """Report a protect run, and surface a generated password exactly once.

        The password is printed last and on its own, so it is the thing left on
        screen. It is not written to the log, and it is only ever shown when
        this tool generated it -- a password the user supplied is theirs
        already, and echoing it would only put it in scrollback.
        """
        if self.as_json:
            payload = _protect_payload(result)
            if generated is not None:
                # Agents need this back or the file they just created is lost.
                with generated.expose() as text:
                    payload["generated_password"] = text
            if password_file is not None:
                payload["password_file"] = str(password_file)
            self.json(payload)
            return

        self.line(
            f"{self._paint(self._mark('ok'), 'ok')} "
            f"{self._paint('PROTECTED', 'ok')}  {result.output.name}"
        )
        self._field("applied", result.protection_applied.value)
        if result.algorithm:
            self._field("algorithm", result.algorithm)
        self._field(
            "size",
            f"{human_size(result.bytes_in)} {self._arrow()} {human_size(result.bytes_out)} "
            f"{self._dot()} {result.duration_s:.2f}s",
        )
        self._hallmark(dict(result.verification))
        self._field("saved to", str(result.output))
        self._field("original", f"{result.source} (unchanged)")
        for warning in result.warnings:
            self.line(
                f"{_INDENT}{self._paint(self._mark('warn'), 'warn')} {self._paint(warning, 'warn')}"
            )

        if password_file is not None:
            self.line()
            self._field("password in", str(password_file))
            self.line(
                f"{_INDENT}{self._paint('Keep that file. Without it this file cannot be opened.', 'warn')}"
            )
        if generated is not None:
            self.line()
            self.line(_INDENT + self._paint(_caption("password"), "brass"))
            with generated.expose() as text:
                self.line(_INDENT + text)
            self.line(
                f"{_INDENT}{self._paint('Save this now. It is shown once, and this tool cannot recover it.', 'warn')}"
            )

    def batch(self, report: BatchReport) -> None:
        if self.as_json:
            self.json(
                {
                    "removed": report.removed,
                    "skipped": report.skipped,
                    "failed": report.failed,
                    "items": [
                        {
                            "source": str(i.source),
                            "outcome": i.outcome.value,
                            "output": str(i.output) if i.output else None,
                            "error_code": i.error_code,
                            "message": i.message,
                        }
                        for i in report.items
                    ],
                }
            )
            return
        for item in report.items:
            kind = {Outcome.REMOVED: "ok", Outcome.SKIPPED: "warn", Outcome.FAILED: "err"}[
                item.outcome
            ]
            target = f" -> {item.output}" if item.output else ""
            self.line(self._paint(f"{self._mark(kind)} {item.source}{target}", kind))
            if item.message:
                self.line(f"    {item.message}")
        self.line()
        self.line(
            f"{report.removed} removed, {report.skipped} skipped, {report.failed} failed "
            f"(of {len(report.items)})"
        )

    def error(self, message: str, remediation: str | None = None, *, code: str = "") -> None:
        if self.as_json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": code or "error",
                        "message": message,
                        "remediation": remediation,
                    },
                    indent=2,
                ),
                file=self.stream,
            )
            return
        print(self._paint(f"{self._mark('err')} {message}", "err"), file=sys.stderr)
        if remediation:
            print(f"  {remediation}", file=sys.stderr)


def _detection_payload(detection: Detection) -> dict[str, Any]:
    return {
        "ok": True,
        "path": str(detection.path),
        "format": detection.format_id.value,
        "format_name": detection.format_name,
        "protection": detection.protection.value,
        "removability": detection.removability.value,
        "algorithm": detection.algorithm,
        "extension_mismatch": detection.extension_mismatch,
        "detail": detection.detail,
    }


def _result_payload(result: RemovalResult) -> dict[str, Any]:
    return {
        "ok": True,
        "source": str(result.source),
        "output": str(result.output),
        "format": result.format_id.value,
        "protection_removed": result.protection_removed.value,
        "algorithm": result.algorithm,
        "bytes_in": result.bytes_in,
        "bytes_out": result.bytes_out,
        "duration_s": round(result.duration_s, 3),
        "verification": result.verification,
        "warnings": list(result.warnings),
    }


def _encode(obj: object) -> Any:
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    return str(obj)


def _protect_payload(result: ProtectResult) -> dict[str, Any]:
    return {
        "ok": True,
        "source": str(result.source),
        "output": str(result.output),
        "format": result.format_id.value,
        "protection_applied": result.protection_applied.value,
        "algorithm": result.algorithm,
        "bytes_in": result.bytes_in,
        "bytes_out": result.bytes_out,
        "duration_s": round(result.duration_s, 3),
        "verification": dict(result.verification),
        "warnings": list(result.warnings),
    }
