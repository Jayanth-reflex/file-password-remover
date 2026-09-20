"""The renderer degrades cleanly and never invents a success."""

from __future__ import annotations

import dataclasses
import io
import json
from pathlib import Path

import pytest

from fpr.cli.output import Renderer, human_size, supports_colour
from fpr.types import (
    BatchItemReport,
    BatchReport,
    Detection,
    FormatId,
    Outcome,
    Protection,
    Removability,
    RemovalResult,
)


class FakeStream(io.StringIO):
    """A StringIO that can pretend to be a narrow terminal.

    ``encoding`` is read-only on ``_io._TextIOBase``, so it is shadowed with a
    property rather than assigned.
    """

    def __init__(self, tty: bool = False, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    @property
    def encoding(self) -> str:  # type: ignore[override]
        return self._encoding

    def isatty(self) -> bool:
        return self._tty


def _detection() -> Detection:
    return Detection(
        path=Path("/tmp/a.pdf"),
        format_id=FormatId.PDF,
        format_name="PDF",
        protection=Protection.USER_PASSWORD,
        removability=Removability.REMOVABLE,
        algorithm="AES-256",
        detail="Encrypted.",
    )


def _result() -> RemovalResult:
    return RemovalResult(
        source=Path("/tmp/a.pdf"),
        output=Path("/tmp/a-unprotected.pdf"),
        format_id=FormatId.PDF,
        protection_removed=Protection.USER_PASSWORD,
        algorithm="AES-256",
        bytes_in=2048,
        bytes_out=1800,
        duration_s=0.25,
        verification={"encrypted": "false", "pages": "3"},
        warnings=("an advisory",),
    )


@pytest.mark.parametrize(
    ("value", "expected"), [(0, "0 B"), (512, "512 B"), (2048, "2.0 KiB"), (5 << 20, "5.0 MiB")]
)
def test_human_size(value: int, expected: str) -> None:
    assert human_size(value) == expected


def test_colour_is_off_when_not_a_tty() -> None:
    assert supports_colour(FakeStream(tty=False)) is False


def test_colour_respects_no_color(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_colour(FakeStream(tty=True)) is False


def test_symbols_fall_back_to_words_on_a_limited_terminal() -> None:
    stream = FakeStream(encoding="ascii")
    renderer = Renderer(stream)
    renderer.result(_result())
    text = stream.getvalue()
    assert "OK" in text
    assert "✓" not in text


def test_result_shows_the_verification_evidence() -> None:
    """The hallmark row: every checked property, as a caption over its value.

    The evidence is what makes a success meaningful, so it is presented rather
    than buried in a comma-separated tail.
    """
    stream = FakeStream()
    Renderer(stream).result(_result())
    text = stream.getvalue()
    assert "ENCRYPTED" in text, "the hallmark captions name what was checked"
    assert "PAGES" in text
    assert "false" in text, "and the values sit under them"
    assert "unchanged" in text
    assert "an advisory" in text


def test_hallmark_captions_and_values_line_up() -> None:
    """A column whose value is wider than its caption must still align."""
    stream = FakeStream()
    Renderer(stream).result(_result())
    lines = [line for line in stream.getvalue().splitlines() if "ENCRYPTED" in line]
    assert lines, "expected a caption row"
    captions = lines[0]
    values = stream.getvalue().splitlines()[stream.getvalue().splitlines().index(captions) + 1]
    assert values.index("false") == captions.index("ENCRYPTED"), "columns drifted"


def test_hallmark_shortens_captions_but_never_values() -> None:
    """The caption is a label; the value is evidence and must stay verbatim."""
    base = _result()
    result = dataclasses.replace(
        base,
        verification={
            "encrypted": "false",
            "content_digest": "456cf7bce5ff12ef",
            "content_scope": "all 3 page(s)",
        },
    )
    stream = FakeStream()
    Renderer(stream).result(result)
    text = stream.getvalue()

    assert "DIGEST" in text, "content_digest is captioned as DIGEST"
    assert "CONTENT_DIGEST" not in text
    for value in result.verification.values():
        assert value in text, f"value {value!r} was altered or dropped"


def test_hallmark_rule_falls_back_to_ascii() -> None:
    stream = FakeStream(encoding="ascii")
    Renderer(stream).result(_result())
    text = stream.getvalue()
    assert "\u2500" not in text, "box drawing must not reach an ascii terminal"
    assert "-" in text, "but the rule is still drawn"


def test_json_result_is_machine_readable() -> None:
    stream = FakeStream()
    Renderer(stream, as_json=True).result(_result())
    payload = json.loads(stream.getvalue())
    assert payload["ok"] is True
    assert payload["verification"]["pages"] == "3"
    assert payload["warnings"] == ["an advisory"]


def test_detection_rendering_flags_an_extension_mismatch() -> None:
    stream = FakeStream()
    base = _detection()
    mismatched = Detection(
        path=base.path,
        format_id=base.format_id,
        format_name=base.format_name,
        protection=base.protection,
        removability=base.removability,
        algorithm=base.algorithm,
        detail=base.detail,
        extension_mismatch=True,
    )
    Renderer(stream).detection(mismatched)
    assert "does not match" in stream.getvalue()


def test_batch_summary_counts_every_outcome() -> None:
    stream = FakeStream()
    report = BatchReport(
        items=(
            BatchItemReport(Path("a"), Outcome.REMOVED, Path("a-out")),
            BatchItemReport(Path("b"), Outcome.SKIPPED, message="nothing to do"),
            BatchItemReport(Path("c"), Outcome.FAILED, message="wrong password"),
        )
    )
    Renderer(stream).batch(report)
    text = stream.getvalue()
    assert "1 removed, 1 skipped, 1 failed" in text
    assert "wrong password" in text


def test_quiet_suppresses_normal_lines_but_not_json() -> None:
    stream = FakeStream()
    Renderer(stream, quiet=True).result(_result())
    assert stream.getvalue() == ""


def test_json_error_payload() -> None:
    stream = FakeStream()
    Renderer(stream, as_json=True).error("boom", "try this", code="TestError")
    payload = json.loads(stream.getvalue())
    assert payload == {
        "ok": False,
        "error": "TestError",
        "message": "boom",
        "remediation": "try this",
    }
