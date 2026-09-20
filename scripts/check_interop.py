#!/usr/bin/env python3
"""Open files produced by the Swift and Kotlin implementations.

A round trip through one implementation proves only that it agrees with itself.
For a decryptor that is weak evidence; for an *encryptor* it is nearly none --
a bug that corrupts the key schedule symmetrically would pass a self round trip
and still produce files nothing else on earth can open.

So each port writes a protected file during its own test run, and this opens
them with the Python implementation and checks the contents came back.

    python3 scripts/check_interop.py build/interop
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fpr import RemovalOptions, Secret, inspect, remove  # noqa: E402
from fpr.testing import fixtures as F  # noqa: E402
from fpr.types import Protection  # noqa: E402

PASSWORD = "interop-fixed-password"  # nosec B105 - matches the ports' test constant


def _check(path: Path, expect_members: dict[str, str] | None) -> None:
    detection = inspect(path)
    if detection.protection is not Protection.USER_PASSWORD:
        raise SystemExit(f"{path.name}: expected an encrypted file, got {detection.protection}")

    opened = remove(
        path,
        Secret.from_text(PASSWORD),
        RemovalOptions(output=path.with_name(f"{path.stem}-opened{path.suffix}"), overwrite=True),
    )
    print(f"  {path.name}: opened, {opened.verification}")

    if expect_members is None:
        return
    import zipfile

    with zipfile.ZipFile(opened.output) as archive:
        actual = {
            info.filename: hashlib.sha256(archive.read(info)).hexdigest()
            for info in archive.infolist()
            if not info.is_dir()
        }
    if actual != expect_members:
        raise SystemExit(f"{path.name}: contents differ after the round trip")
    print(f"  {path.name}: {len(actual)} member(s) match the original byte for byte")


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path("build/interop")
    artifacts = sorted(root.glob("*-protected.*")) if root.is_dir() else []
    if not artifacts:
        print(f"no interop artifacts in {root}; run the Swift or Kotlin tests first")
        return 0

    # The ports protect the corpus's plain ZIP, so its members are known.
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(F.make_zip_plain())) as archive:
        zip_members = {
            info.filename: hashlib.sha256(archive.read(info)).hexdigest()
            for info in archive.infolist()
            if not info.is_dir()
        }

    print(f"checking {len(artifacts)} artifact(s) from {root}:")
    for path in artifacts:
        if path.name.endswith("-opened" + path.suffix):
            continue
        _check(path, zip_members if path.suffix == ".zip" else None)
    print("all interop artifacts opened with the Python implementation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
