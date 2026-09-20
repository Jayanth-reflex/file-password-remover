#!/usr/bin/env python3
"""Generate the cross-language test-vector corpus.

The Swift (iOS) and Kotlin (Android) test suites decrypt files produced here.
Nothing binary is committed: CI runs this before `swift test` / `gradle test`.

    python3 scripts/gen_vectors.py build/vectors
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fpr.testing.vectors import export_corpus  # noqa: E402


def main(argv: list[str]) -> int:
    dest = Path(argv[1]) if len(argv) > 1 else Path("build/vectors")
    dest.mkdir(parents=True, exist_ok=True)
    manifest_path = export_corpus(dest)
    manifest = json.loads(manifest_path.read_text())
    print(f"{len(manifest['vectors'])} vectors -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
