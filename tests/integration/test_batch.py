"""Batch runs: everything is attempted, everything is reported."""

from __future__ import annotations

from pathlib import Path

from fpr import RemovalOptions, Secret
from fpr.batch import collect_inputs, run_batch
from fpr.testing import fixtures as F
from fpr.types import Outcome

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD, WRONG_PASSWORD


def _folder(tmp_path: Path) -> Path:
    folder = tmp_path / "docs"
    (folder / "nested").mkdir(parents=True)
    (folder / "a.pdf").write_bytes(
        F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    )
    (folder / "b.docx").write_bytes(F.make_encrypted_ooxml(F.make_docx()))
    (folder / "plain.pdf").write_bytes(F.make_pdf())
    (folder / "notes.txt").write_bytes(b"hello")
    (folder / "nested" / "c.zip").write_bytes(F.make_zip_aes())
    return folder


def test_collect_is_not_recursive_by_default(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    assert len(collect_inputs([folder])) == 4


def test_collect_recurses_when_asked(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    assert len(collect_inputs([folder], recursive=True)) == 5


def test_collect_filters_by_pattern(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    found = collect_inputs([folder], recursive=True, patterns=["*.pdf"])
    assert {p.name for p in found} == {"a.pdf", "plain.pdf"}


def test_collect_deduplicates(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    assert len(collect_inputs([folder / "a.pdf", folder / "a.pdf"])) == 1


def test_every_item_is_attempted_and_classified(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        report = run_batch(collect_inputs([folder], recursive=True), pw)
    by_name = {item.source.name: item for item in report.items}
    assert by_name["a.pdf"].outcome is Outcome.REMOVED
    assert by_name["b.docx"].outcome is Outcome.REMOVED
    assert by_name["c.zip"].outcome is Outcome.REMOVED
    assert by_name["plain.pdf"].outcome is Outcome.SKIPPED  # nothing to remove
    assert by_name["notes.txt"].outcome is Outcome.SKIPPED  # unsupported type
    assert report.removed == 3
    assert report.failed == 0


def test_a_wrong_password_fails_every_item_without_stopping(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    with Secret.from_text(WRONG_PASSWORD) as pw:
        report = run_batch(collect_inputs([folder], recursive=True), pw)
    assert report.failed == 3
    assert report.removed == 0
    assert all(
        i.error_code == "IncorrectPasswordError"
        for i in report.items
        if i.outcome is Outcome.FAILED
    )


def test_stop_on_error_halts_the_run(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    inputs = collect_inputs([folder], recursive=True)
    with Secret.from_text(WRONG_PASSWORD) as pw:
        report = run_batch(inputs, pw, stop_on_error=True)
    assert len(report.items) < len(inputs)


def test_progress_hook_sees_every_item(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    inputs = collect_inputs([folder], recursive=True)
    seen: list[str] = []
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        run_batch(inputs, pw, on_progress=lambda _index, _total, path: seen.append(path.name))
    assert len(seen) == len(inputs)


def test_outputs_land_in_the_requested_directory(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    outdir = tmp_path / "clean"
    outdir.mkdir()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        report = run_batch(
            collect_inputs([folder], recursive=True), pw, RemovalOptions(output_dir=outdir)
        )
    assert report.removed == 3
    assert {p.name for p in outdir.iterdir()} == {
        "a-unprotected.pdf",
        "b-unprotected.docx",
        "c-unprotected.zip",
    }
