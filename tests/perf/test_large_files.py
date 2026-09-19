"""Performance and memory characteristics on files larger than a toy fixture.

These are marked ``slow`` and excluded from the default run. They exist to
catch the two regressions that actually hurt: accidentally reading a whole
archive into memory, and accidentally making verification quadratic.
"""

from __future__ import annotations

import os
import time
import zipfile
from pathlib import Path

import pytest

from fpr import Secret, remove

from ..conftest import SAMPLE_PASSWORD

pytestmark = pytest.mark.slow

MB = 1 << 20


def _rss_mb() -> float | None:
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes, Linux reports kilobytes.
    return usage / MB if os.uname().sysname == "Darwin" else usage / 1024


def test_large_pdf_throughput(write) -> None:
    from fpr.testing import fixtures as F

    blob = F.make_pdf(F.PdfSpec(pages=600, user=SAMPLE_PASSWORD, owner="o"))
    path = write("big.pdf", blob)
    started = time.monotonic()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    elapsed = time.monotonic() - started
    assert result.verification["encrypted"] == "false"
    # 600 pages is above VERIFY_PAGE_CAP, so verification samples and says so.
    assert "of 600 page(s)" in result.verification["content_scope"]
    assert elapsed < 60, f"600-page PDF took {elapsed:.1f}s"


def test_large_zip_streams_rather_than_buffering(tmp_path: Path) -> None:
    """A 200 MiB archive must not cost 200 MiB of RSS.

    The fixture is written straight to disk rather than through a BytesIO:
    ``ru_maxrss`` is a high-water mark, so a 200 MiB buffer here would poison
    the baseline and make the memory assertion meaningless.
    """
    import pyzipper

    payload = os.urandom(MB)  # incompressible, so the archive is honestly large
    path = tmp_path / "big.zip"
    with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_STORED) as zf:
        zf.setpassword(SAMPLE_PASSWORD.encode())
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        for i in range(200):
            zf.writestr(f"blob-{i:03d}.bin", payload)

    baseline = _rss_mb()
    started = time.monotonic()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        result = remove(path, pw)
    elapsed = time.monotonic() - started
    peak = _rss_mb()

    assert result.verification["encrypted"] == "false"
    with zipfile.ZipFile(result.output) as zf:
        assert len(zf.namelist()) == 200
        assert zf.read("blob-000.bin") == payload
    if baseline is not None and peak is not None:
        assert peak - baseline < 120, f"RSS grew {peak - baseline:.0f} MiB for a 200 MiB archive"
    assert elapsed < 180, f"200 MiB archive took {elapsed:.1f}s"


def test_many_small_files_in_one_batch(tmp_path: Path) -> None:
    from fpr.batch import collect_inputs, run_batch
    from fpr.testing import fixtures as F

    folder = tmp_path / "many"
    folder.mkdir()
    blob = F.make_pdf(F.PdfSpec(pages=1, user=SAMPLE_PASSWORD, owner="o"))
    for i in range(100):
        (folder / f"doc-{i:03d}.pdf").write_bytes(blob)
    started = time.monotonic()
    with Secret.from_text(SAMPLE_PASSWORD) as pw:
        report = run_batch(collect_inputs([folder]), pw)
    elapsed = time.monotonic() - started
    assert report.removed == 100
    assert elapsed < 60, f"100 small PDFs took {elapsed:.1f}s"
