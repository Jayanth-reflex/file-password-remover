"""The cross-language vector corpus.

The iOS and Android ports reimplement the adapters in Swift and Kotlin. They
are verified against files generated *here*, from the specifications, so a
port is proved against the format rather than against a mirror of itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fpr.testing.vectors import export_corpus


def test_export_corpus_writes_a_manifest_listing_files_that_exist(tmp_path: Path) -> None:
    manifest_path = export_corpus(tmp_path)

    manifest = json.loads(manifest_path.read_text())
    assert manifest["vectors"], "corpus must contain at least one vector"
    for vector in manifest["vectors"]:
        assert (tmp_path / vector["file"]).is_file(), f"{vector['id']} missing on disk"


def test_archive_vectors_carry_plaintext_digests_for_each_member(tmp_path: Path) -> None:
    """A port must prove it recovered the *content*, not merely that it did not throw."""
    manifest = json.loads(export_corpus(tmp_path).read_text())
    by_id = {vector["id"]: vector for vector in manifest["vectors"]}

    members = by_id["zip-aes256"]["expect"]["members"]
    assert [member["name"] for member in members] == [
        "notes.txt",
        "data/values.csv",
        "data/blob.bin",
    ]
    for member in members:
        assert len(member["sha256"]) == 64
        assert member["size"] > 0


def test_corpus_still_generates_without_the_optional_sevenzip_extra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """py7zr is an optional extra (ADR-0006), so the corpus must not need it.

    Without this, a default install cannot even build its own test fixtures --
    which is how the corpus broke the `default install has no optional extra`
    CI job.
    """
    import builtins

    real_import = builtins.__import__

    def refuse_py7zr(name: str, *args: object, **kwargs: object) -> object:
        if name == "py7zr":
            raise ImportError("No module named 'py7zr'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_py7zr)

    manifest = json.loads(export_corpus(tmp_path).read_text())

    formats = {vector["format"] for vector in manifest["vectors"]}
    assert "7z" not in formats, "7-Zip vectors must be skipped when py7zr is absent"
    assert "pdf" in formats and "zip" in formats, "everything else must still be generated"
