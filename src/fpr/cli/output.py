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
import sys
from pathlib import Path
from typing import Any, TextIO

from ..types import BatchReport, Detection, Outcome, RemovalResult

__all__ = ["Renderer", "supports_colour", "human_size"]

_RESET = "\033[0m"
_COLOURS = {"ok": "\033[32m", "warn": "\033[33m", "err": "\033[31m", "dim": "\033[2m"}


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

    # ------------------------------------------------------------ primitives
    def _paint(self, text: str, kind: str) -> str:
        if not self.colour:
            return text
        return f"{_COLOURS.get(kind, '')}{text}{_RESET}"

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
        self.line(f"{detection.path}")
        self.line(f"  format       {detection.format_name} ({detection.format_id.value})")
        self.line(f"  protection   {detection.protection.value}")
        if detection.algorithm:
            self.line(f"  algorithm    {detection.algorithm}")
        self.line(f"  removable    {detection.removability.value}")
        if detection.extension_mismatch:
            self.line(
                "  "
                + self._paint(
                    f"{self._mark('warn')} the file extension does not match its contents",
                    "warn",
                )
            )
        if detection.detail:
            self.line(f"  note         {detection.detail}")

    def result(self, result: RemovalResult) -> None:
        if self.as_json:
            self.json(_result_payload(result))
            return
        self.line(self._paint(f"{self._mark('ok')} {result.output}", "ok"))
        self.line(f"  removed      {result.protection_removed.value}")
        if result.algorithm:
            self.line(f"  algorithm    {result.algorithm}")
        self.line(
            f"  size         {human_size(result.bytes_in)} -> {human_size(result.bytes_out)} "
            f"in {result.duration_s:.2f}s"
        )
        proof = ", ".join(f"{k}={v}" for k, v in result.verification.items())
        self.line(f"  verified     {proof}")
        self.line(f"  original     {result.source} (unchanged)")
        for warning in result.warnings:
            self.line(self._paint(f"  {self._mark('warn')} {warning}", "warn"))

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
