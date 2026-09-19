#!/usr/bin/env python3
"""Check that every relative Markdown link in the repository resolves.

Documentation that points at files which do not exist is worse than no
documentation: it implies a level of care that is not there. This runs in CI.

    python scripts/check_docs.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def main() -> int:
    broken: list[str] = []
    checked = 0
    for source in sorted(ROOT.rglob("*.md")):
        if any(part in {".venv", "build", "dist", "artifacts", ".git"} for part in source.parts):
            continue
        for match in LINK.finditer(source.read_text(encoding="utf-8")):
            target = match.group(1).split("#", 1)[0].strip()
            if not target or target.startswith(SKIP_PREFIXES):
                continue
            checked += 1
            resolved = (source.parent / target).resolve()
            if not resolved.exists():
                broken.append(f"{source.relative_to(ROOT)} -> {target}")

    print(f"checked {checked} relative links in {len(list(ROOT.rglob('*.md')))} files")
    for item in broken:
        print(f"  BROKEN  {item}")
    if broken:
        print(f"\n{len(broken)} broken link(s)")
        return 1
    print("all relative links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
