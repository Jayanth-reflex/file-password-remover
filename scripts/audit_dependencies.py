#!/usr/bin/env python3
"""Refresh the dependency licence and advisory evidence.

Writes two files that docs/research/01-dependency-license-analysis.md cites:

    docs/research/evidence/pypi-metadata.json   versions, upload dates, licences
    docs/research/evidence/osv-scan-deps.json   advisories for the pinned versions

This is the one script in the repository that talks to the network, and it is
a *developer* tool: nothing in the installed package imports it, and the test
suite asserts that the package itself contains no network code.

    python scripts/audit_dependencies.py [--offline]
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import sys
import urllib.request
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "research" / "evidence"

PACKAGES = [
    "pikepdf",
    "msoffcrypto-tool",
    "pyzipper",
    "py7zr",
    "cryptography",
    "olefile",
    "lxml",
    "pycryptodomex",
    "pillow",
]


def installed_version(name: str) -> str | None:
    try:
        return md.version(name)
    except md.PackageNotFoundError:
        return None


def pypi_metadata() -> dict[str, object]:
    out: dict[str, object] = {}
    for name in PACKAGES:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as fh:
            data = json.load(fh)
        info, releases = data["info"], data["releases"]

        def uploaded(version: str, releases: dict = releases) -> str | None:
            files = releases.get(version) or []
            return min((f["upload_time_iso_8601"] for f in files), default=None)

        dated = sorted(
            ((v, uploaded(v)) for v in releases if uploaded(v)),
            key=lambda item: item[1],
            reverse=True,
        )
        out[name] = {
            "latest": info["version"],
            "latest_upload": uploaded(info["version"]),
            "license": info.get("license_expression") or info.get("license"),
            "requires_python": info.get("requires_python"),
            "project_urls": info.get("project_urls") or {},
            "installed": installed_version(name),
            "recent": dated[:5],
        }
    return out


def osv_scan() -> dict[str, object]:
    out: dict[str, object] = {}
    for name in PACKAGES:
        version = installed_version(name)
        if version is None:
            out[name] = {"version": None, "skipped": "not installed"}
            continue
        body = json.dumps(
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        ).encode()
        request = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as fh:
            data = json.load(fh)
        vulns = data.get("vulns", [])
        out[name] = {
            "version": version,
            "vuln_count": len(vulns),
            "vulns": [{"id": v["id"], "summary": v.get("summary", "")} for v in vulns],
        }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true", help="only print installed versions; fetch nothing"
    )
    args = parser.parse_args()

    if args.offline:
        for name in PACKAGES:
            print(f"{name:20} {installed_version(name) or 'not installed'}")
        return 0

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    metadata = pypi_metadata()
    (EVIDENCE / "pypi-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    advisories = osv_scan()
    (EVIDENCE / "osv-scan-deps.json").write_text(json.dumps(advisories, indent=2) + "\n")

    total = sum(
        entry.get("vuln_count", 0) for entry in advisories.values() if isinstance(entry, dict)
    )
    for name, entry in advisories.items():
        if isinstance(entry, dict):
            print(
                f"{name:20} {entry.get('version')!s:16} advisories={entry.get('vuln_count', '-')}"
            )
    print(f"\nwrote {EVIDENCE}/pypi-metadata.json and osv-scan-deps.json")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
