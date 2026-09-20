"""The cross-language vector corpus.

The iOS and Android ports reimplement the adapters in Swift and Kotlin. They
are verified against files generated *here*, from the specifications, so a
port is proved against the format rather than against a mirror of itself.
"""

from __future__ import annotations

import json
from pathlib import Path

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
