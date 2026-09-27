"""Every feature, through the installed executable.

`test_journeys.py` follows a person through several commands. This file is the
other axis: one row per thing the tool claims to do, each driven the way a user
drives it -- the console script, a working directory of their own, and nothing
but argv, stdin and the exit code to talk to it with.

The format matrix is the core of it. Removal is claimed for four PDF
revisions, three Office applications, three ZIP key sizes plus ZipCrypto, and
7-Zip with and without encrypted headers; each of those is decrypted here and
the result read back by an independent reader, not by this tool.
"""

from __future__ import annotations

import io
import json
import os
import time
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from fpr.errors import ExitCode
from fpr.testing import fixtures as F

from ..conftest import OWNER_PASSWORD, SAMPLE_PASSWORD, WRONG_PASSWORD

pytestmark = pytest.mark.e2e

POSIX = os.name != "nt"


def _has_py7zr() -> bool:
    try:
        import py7zr  # noqa: F401
    except ImportError:
        return False
    return True


needs_7z = pytest.mark.skipif(not _has_py7zr(), reason="the [sevenzip] extra is not installed")


# ------------------------------------------------------------------ helpers
def _inspect(fpr, name: str) -> dict:
    result = fpr("--json", "inspect", name)
    assert result.returncode == ExitCode.OK, result.stderr
    (found,) = json.loads(result.stdout)["results"]
    return dict(found)


def _pdf_pages(path: Path) -> int:
    import pikepdf

    with pikepdf.open(path) as pdf:
        assert not pdf.is_encrypted
        return len(pdf.pages)


def _zip_members(data: bytes, password: str | None = None) -> dict[str, bytes]:
    """Read a ZIP with an independent implementation: pyzipper for AES, stdlib otherwise."""
    import pyzipper

    with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
        if password is not None:
            archive.setpassword(password.encode())
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


# ------------------------------------------------------ the removal matrix
# (id, file name, bytes, how to check the unprotected output)
Check = Callable[[Path], None]


def _pdf_ok(path: Path) -> None:
    assert _pdf_pages(path) == 3


def _ooxml_ok(path: Path) -> None:
    with zipfile.ZipFile(path) as package:
        assert "[Content_Types].xml" in package.namelist()


def _zip_ok(path: Path) -> None:
    expected = _zip_members(F.make_zip_plain())
    assert _zip_members(path.read_bytes()) == expected


def _sevenzip_ok(path: Path) -> None:
    import py7zr

    with py7zr.SevenZipFile(path) as archive:
        assert not archive.needs_password()
        assert archive.getnames()


REMOVABLE: list[tuple[str, str, Callable[[], bytes], Check]] = [
    *[
        (
            f"pdf-r{rev}",
            f"r{rev}.pdf",
            (
                lambda rev=rev: F.make_pdf(
                    F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD, revision=rev)
                )
            ),
            _pdf_ok,
        )
        for rev in (2, 3, 4, 6)
    ],
    ("docx", "letter.docx", lambda: F.make_encrypted_ooxml(F.make_docx()), _ooxml_ok),
    ("xlsx", "ledger.xlsx", lambda: F.make_encrypted_ooxml(F.make_xlsx()), _ooxml_ok),
    ("pptx", "deck.pptx", lambda: F.make_encrypted_ooxml(F.make_pptx()), _ooxml_ok),
    *[
        (
            f"zip-aes-{bits}",
            f"aes{bits}.zip",
            (lambda bits=bits: F.make_zip_aes(bits=bits)),
            _zip_ok,
        )
        for bits in (128, 192, 256)
    ],
    ("zip-zipcrypto", "legacy.zip", F.make_zip_zipcrypto, _zip_ok),
]


@pytest.mark.parametrize(
    ("name", "make", "check"),
    [pytest.param(n, m, c, id=i) for i, n, m, c in REMOVABLE],
)
def test_every_supported_protection_is_removed_and_read_back(
    fpr, tmp_path: Path, name: str, make: Callable[[], bytes], check: Check
) -> None:
    source = tmp_path / name
    source.write_bytes(make())
    before = source.read_bytes()

    seen = _inspect(fpr, name)
    assert seen["protection"] != "none"
    assert seen["removability"] == "removable"

    result = fpr("--json", "remove", name, "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr
    output = tmp_path / json.loads(result.stdout)["output"]

    check(output)
    assert _inspect(fpr, output.name)["protection"] == "none"
    assert source.read_bytes() == before, "the original was modified"


@pytest.mark.parametrize(
    ("name", "make"),
    [pytest.param(n, m, id=i) for i, n, m, _ in REMOVABLE],
)
def test_a_wrong_password_is_rejected_for_every_format(
    fpr, tmp_path: Path, name: str, make: Callable[[], bytes]
) -> None:
    (tmp_path / name).write_bytes(make())
    result = fpr("remove", name, "--password-stdin", "-o", "out.bin", stdin=WRONG_PASSWORD)
    assert result.returncode == ExitCode.WRONG_PASSWORD
    assert not (tmp_path / "out.bin").exists()


@needs_7z
@pytest.mark.parametrize("encrypt_header", [False, True], ids=["7z-aes", "7z-aes-header"])
def test_seven_zip_is_removed_and_read_back(fpr, tmp_path: Path, encrypt_header: bool) -> None:
    (tmp_path / "vault.7z").write_bytes(F.make_sevenzip(encrypt_header=encrypt_header))
    result = fpr("--json", "remove", "vault.7z", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr
    _sevenzip_ok(tmp_path / json.loads(result.stdout)["output"])


# -------------------------------------------------------- the protect matrix
PROTECTABLE: list[tuple[str, str, Callable[[], bytes]]] = [
    ("pdf", "notes.pdf", F.make_pdf),
    ("zip", "bundle.zip", F.make_zip_plain),
]


@pytest.mark.parametrize(("name", "make"), [pytest.param(n, m, id=i) for i, n, m in PROTECTABLE])
def test_protect_then_remove_returns_the_same_content(
    fpr, tmp_path: Path, name: str, make: Callable[[], bytes]
) -> None:
    (tmp_path / name).write_bytes(make())
    locked = fpr("--json", "protect", name, "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert locked.returncode == ExitCode.OK, locked.stderr
    protected = tmp_path / json.loads(locked.stdout)["output"]
    assert _inspect(fpr, protected.name)["protection"] != "none"

    opened = fpr(
        "--json",
        "remove",
        protected.name,
        "--password-stdin",
        "-o",
        f"back-{name}",
        stdin=SAMPLE_PASSWORD,
    )
    assert opened.returncode == ExitCode.OK, opened.stderr
    back = tmp_path / f"back-{name}"
    if name.endswith(".zip"):
        assert _zip_members(back.read_bytes()) == _zip_members(make())
    else:
        assert _pdf_pages(back) == 3


@pytest.mark.parametrize(
    ("name", "make"),
    [
        pytest.param("letter.docx", F.make_docx, id="docx"),
        pytest.param("old.doc", lambda: F.make_legacy_doc(encrypted=False), id="legacy-doc"),
    ],
)
def test_protect_refuses_formats_it_cannot_encrypt(
    fpr, tmp_path: Path, name: str, make: Callable[[], bytes]
) -> None:
    """Refusing is the feature: the alternative is an unencrypted copy named '-protected'."""
    (tmp_path / name).write_bytes(make())
    result = fpr("protect", name, "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode != ExitCode.OK
    assert not list(tmp_path.glob("*-protected*"))


# --------------------------------------------------------- password routes
@pytest.fixture
def locked_pdf(tmp_path: Path) -> Path:
    target = tmp_path / "locked.pdf"
    target.write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))
    return target


def test_password_from_a_file(fpr, locked_pdf: Path, tmp_path: Path) -> None:
    secret = tmp_path / "pw.txt"
    secret.write_text(SAMPLE_PASSWORD + "\n")
    if POSIX:
        secret.chmod(0o600)
    result = fpr("remove", "locked.pdf", "--password-file", str(secret))
    assert result.returncode == ExitCode.OK, result.stderr


@pytest.mark.skipif(not POSIX, reason="a readable-by-others check needs POSIX permissions")
def test_a_world_readable_password_file_is_warned_about(fpr, locked_pdf: Path, tmp_path: Path):
    secret = tmp_path / "pw.txt"
    secret.write_text(SAMPLE_PASSWORD)
    secret.chmod(0o644)
    result = fpr("remove", "locked.pdf", "--password-file", str(secret))
    assert result.returncode == ExitCode.OK
    assert "readable" in result.stderr.lower()


@pytest.mark.skipif(not POSIX, reason="inheriting an arbitrary fd is POSIX-only")
def test_password_from_an_inherited_file_descriptor(fpr_bin: Path, locked_pdf: Path) -> None:
    import subprocess

    read_end, write_end = os.pipe()
    os.write(write_end, SAMPLE_PASSWORD.encode())
    os.close(write_end)
    try:
        result = subprocess.run(
            [str(fpr_bin), "remove", "locked.pdf", "--password-fd", str(read_end)],
            cwd=locked_pdf.parent,
            pass_fds=(read_end,),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    finally:
        os.close(read_end)
    assert result.returncode == ExitCode.OK, result.stderr


def test_password_from_the_environment_works_and_warns(fpr, locked_pdf: Path) -> None:
    result = fpr(
        "remove", "locked.pdf", "--password-env", "FPR_E2E_PW", env={"FPR_E2E_PW": SAMPLE_PASSWORD}
    )
    assert result.returncode == ExitCode.OK, result.stderr
    assert "warning" in result.stderr.lower()


def test_a_password_on_the_command_line_is_refused(fpr, locked_pdf: Path) -> None:
    result = fpr("remove", "locked.pdf", "--password", SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.USAGE
    assert SAMPLE_PASSWORD not in result.stdout + result.stderr


def test_two_password_sources_are_refused(fpr, locked_pdf: Path, tmp_path: Path) -> None:
    secret = tmp_path / "pw.txt"
    secret.write_text(SAMPLE_PASSWORD)
    result = fpr(
        "remove",
        "locked.pdf",
        "--password-stdin",
        "--password-file",
        str(secret),
        stdin=SAMPLE_PASSWORD,
    )
    assert result.returncode == ExitCode.USAGE


def test_no_password_and_no_terminal_fails_instead_of_hanging(fpr, locked_pdf: Path) -> None:
    """The prompt is only offered to a real terminal; stdin here is /dev/null."""
    result = fpr("remove", "locked.pdf")
    assert result.returncode != ExitCode.OK
    assert not list(locked_pdf.parent.glob("*-unprotected*"))


# ----------------------------------------------------------- output options
def test_output_path(fpr, locked_pdf: Path, tmp_path: Path) -> None:
    result = fpr(
        "remove", "locked.pdf", "-o", "exact.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD
    )
    assert result.returncode == ExitCode.OK
    assert (tmp_path / "exact.pdf").exists()


def test_output_directory_is_created(fpr, locked_pdf: Path, tmp_path: Path) -> None:
    result = fpr(
        "remove",
        "locked.pdf",
        "--output-dir",
        "out/deeper",
        "--password-stdin",
        stdin=SAMPLE_PASSWORD,
    )
    assert result.returncode == ExitCode.OK, result.stderr
    assert (tmp_path / "out" / "deeper" / "locked-unprotected.pdf").exists()


def test_custom_suffix(fpr, locked_pdf: Path, tmp_path: Path) -> None:
    result = fpr(
        "remove", "locked.pdf", "--suffix", "-open", "--password-stdin", stdin=SAMPLE_PASSWORD
    )
    assert result.returncode == ExitCode.OK
    assert (tmp_path / "locked-open.pdf").exists()


def test_an_existing_output_is_not_clobbered_without_overwrite(
    fpr, locked_pdf: Path, tmp_path: Path
) -> None:
    existing = tmp_path / "locked-unprotected.pdf"
    existing.write_bytes(b"precious")
    refused = fpr("remove", "locked.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert refused.returncode == ExitCode.OUTPUT_EXISTS
    assert existing.read_bytes() == b"precious"

    replaced = fpr("remove", "locked.pdf", "--overwrite", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert replaced.returncode == ExitCode.OK
    assert existing.read_bytes() != b"precious"


def test_in_place_replaces_the_original_and_leaves_nothing_else(
    fpr, locked_pdf: Path, tmp_path: Path
) -> None:
    result = fpr("remove", "locked.pdf", "--in-place", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr
    assert _pdf_pages(locked_pdf) == 3
    assert sorted(p.name for p in tmp_path.iterdir()) == ["locked.pdf"]


def test_protect_has_no_in_place(fpr, tmp_path: Path) -> None:
    (tmp_path / "notes.pdf").write_bytes(F.make_pdf())
    result = fpr("protect", "notes.pdf", "--in-place", "--generate")
    assert result.returncode == ExitCode.USAGE


def test_timestamps_are_preserved_unless_told_otherwise(
    fpr, locked_pdf: Path, tmp_path: Path
) -> None:
    long_ago = time.mktime((2001, 2, 3, 4, 5, 6, 0, 0, -1))
    os.utime(locked_pdf, (long_ago, long_ago))

    kept = fpr("remove", "locked.pdf", "-o", "kept.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert kept.returncode == ExitCode.OK
    assert abs((tmp_path / "kept.pdf").stat().st_mtime - long_ago) < 2

    fresh = fpr(
        "remove",
        "locked.pdf",
        "-o",
        "fresh.pdf",
        "--no-preserve-timestamps",
        "--password-stdin",
        stdin=SAMPLE_PASSWORD,
    )
    assert fresh.returncode == ExitCode.OK
    assert (tmp_path / "fresh.pdf").stat().st_mtime - long_ago > 3600


# ------------------------------------------------------ restrictions/policy
@pytest.fixture
def restricted_pdf(tmp_path: Path) -> Path:
    target = tmp_path / "restricted.pdf"
    target.write_bytes(
        F.make_pdf(F.PdfSpec(owner=OWNER_PASSWORD, deny_print=True, deny_extract=True))
    )
    return target


def test_restrictions_are_refused_without_the_flag(fpr, restricted_pdf: Path) -> None:
    result = fpr("remove", "restricted.pdf", "--password-stdin", stdin=OWNER_PASSWORD)
    assert result.returncode == ExitCode.POLICY_REFUSED


def test_restrictions_need_the_owner_password(fpr, restricted_pdf: Path) -> None:
    result = fpr(
        "remove",
        "restricted.pdf",
        "--remove-restrictions",
        "--password-stdin",
        stdin=WRONG_PASSWORD,
    )
    assert result.returncode == ExitCode.WRONG_PASSWORD


def test_restrictions_are_cleared_with_the_owner_password(
    fpr, restricted_pdf: Path, tmp_path: Path
) -> None:
    result = fpr(
        "remove",
        "restricted.pdf",
        "--remove-restrictions",
        "--password-stdin",
        stdin=OWNER_PASSWORD,
    )
    assert result.returncode == ExitCode.OK, result.stderr
    import pikepdf

    with pikepdf.open(tmp_path / "restricted-unprotected.pdf") as pdf:
        assert pdf.allow.extract and pdf.allow.print_highres


def test_word_editing_restrictions_are_refused_as_a_bypass(fpr, tmp_path: Path) -> None:
    (tmp_path / "locked.docx").write_bytes(F.make_docx_restricted())
    result = fpr("remove", "locked.docx", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.POLICY_REFUSED


def test_legacy_office_is_detected_and_gated_behind_experimental(fpr, tmp_path: Path) -> None:
    (tmp_path / "old.doc").write_bytes(F.make_legacy_doc(encrypted=True))
    seen = _inspect(fpr, "old.doc")
    assert seen["format"] == "legacy-office"
    gated = fpr("remove", "old.doc", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert gated.returncode == ExitCode.POLICY_REFUSED
    assert "experimental" in gated.stderr.lower()


# -------------------------------------------------------------- exit codes
def test_an_unsupported_format_exits_four(fpr, tmp_path: Path) -> None:
    (tmp_path / "thing.rar").write_bytes(F.RAR_STUB)
    result = fpr("remove", "thing.rar", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.UNSUPPORTED_FORMAT


def test_a_damaged_file_exits_five(fpr, tmp_path: Path) -> None:
    encrypted = F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD))
    (tmp_path / "broken.pdf").write_bytes(F.truncate(encrypted))
    result = fpr("remove", "broken.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.CORRUPT_FILE


def test_a_file_with_nothing_to_remove_exits_six(fpr, tmp_path: Path) -> None:
    (tmp_path / "plain.pdf").write_bytes(F.make_pdf())
    result = fpr("remove", "plain.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.NOT_PROTECTED


def test_a_missing_file_is_a_usage_error_not_a_crash(fpr) -> None:
    result = fpr("inspect", "does-not-exist.pdf")
    assert result.returncode in {ExitCode.USAGE, ExitCode.IO_ERROR}
    assert "Traceback" not in result.stderr


# ------------------------------------------------------------------- batch
@pytest.fixture
def inbox(tmp_path: Path) -> Path:
    folder = tmp_path / "inbox"
    (folder / "nested").mkdir(parents=True)
    (folder / "a.zip").write_bytes(F.make_zip_aes())
    (folder / "nested" / "b.zip").write_bytes(F.make_zip_aes())
    (folder / "c.zip").write_bytes(F.make_zip_aes(password="some other password"))
    (folder / "notes.txt").write_text("not a format")
    return folder


def test_a_batch_with_one_failure_reports_partial_failure(fpr, inbox: Path) -> None:
    result = fpr(
        "--json",
        "remove",
        "inbox",
        "--recursive",
        "--pattern",
        "*.zip",
        "--output-dir",
        "clean",
        "--password-stdin",
        stdin=SAMPLE_PASSWORD,
    )
    assert result.returncode == ExitCode.PARTIAL_FAILURE
    report = json.loads(result.stdout)
    assert (report["removed"], report["failed"]) == (2, 1)


def test_stop_on_error_halts_the_batch(fpr, inbox: Path) -> None:
    result = fpr(
        "--json",
        "remove",
        "inbox",
        "--recursive",
        "--pattern",
        "*.zip",
        "--stop-on-error",
        "--output-dir",
        "clean",
        "--password-stdin",
        stdin=SAMPLE_PASSWORD,
    )
    assert result.returncode != ExitCode.OK
    report = json.loads(result.stdout)
    assert report["failed"] == 1
    assert report["removed"] + report["failed"] + report["skipped"] <= 3


def test_inspect_walks_a_directory(fpr, inbox: Path) -> None:
    result = fpr("--json", "inspect", "inbox", "--recursive", "--pattern", "*.zip")
    assert result.returncode == ExitCode.OK
    assert len(json.loads(result.stdout)["results"]) == 3


# ---------------------------------------------------------- global options
def test_quiet_prints_nothing_on_success(fpr, locked_pdf: Path) -> None:
    result = fpr("-q", "remove", "locked.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK
    assert result.stdout == ""


def test_verbose_logging_never_contains_the_password(fpr, locked_pdf: Path) -> None:
    result = fpr("-vv", "remove", "locked.pdf", "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK
    assert result.stderr, "-vv produced no log at all"
    assert SAMPLE_PASSWORD not in result.stdout + result.stderr


def test_errors_are_json_when_json_was_asked_for(fpr, locked_pdf: Path) -> None:
    result = fpr("--json", "remove", "locked.pdf", "--password-stdin", stdin=WRONG_PASSWORD)
    assert result.returncode == ExitCode.WRONG_PASSWORD
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]


def test_forced_colour_reaches_a_pipe(fpr) -> None:
    result = fpr(env={"FPR_FORCE_COLOR": "1", "NO_COLOR": None})
    assert "\033[" in result.stdout


def test_no_color_wins_over_forced_colour(fpr) -> None:
    result = fpr(env={"FPR_FORCE_COLOR": "1", "NO_COLOR": "1"})
    assert "\033[" not in result.stdout


def test_generated_passwords_are_distinct_and_strong(fpr, tmp_path: Path) -> None:
    seen = set()
    for index in range(3):
        name = f"n{index}.pdf"
        (tmp_path / name).write_bytes(F.make_pdf())
        payload = json.loads(fpr("--json", "protect", name, "--generate").stdout)
        password = payload["generated_password"]
        assert len(password.replace("-", "")) >= 20
        seen.add(password)
    assert len(seen) == 3


@pytest.mark.skipif(not POSIX, reason="owner-only file modes are POSIX; see threat model R-24")
def test_password_out_is_owner_only(fpr, tmp_path: Path) -> None:
    (tmp_path / "notes.pdf").write_bytes(F.make_pdf())
    result = fpr("protect", "notes.pdf", "--generate", "--password-out", "pw.txt")
    assert result.returncode == ExitCode.OK
    assert (tmp_path / "pw.txt").stat().st_mode & 0o077 == 0


# ----------------------------------------------------- awkward file names
AWKWARD_NAMES = [
    pytest.param("with spaces.pdf", id="spaces"),
    pytest.param("résumé.pdf", id="latin-1"),
    pytest.param("报告.pdf", id="cjk"),
    pytest.param("😀 emoji.pdf", id="emoji"),
]


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_awkward_names_work_end_to_end(fpr, tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))
    assert fpr("inspect", name).returncode == ExitCode.OK
    result = fpr("remove", name, "--password-stdin", stdin=SAMPLE_PASSWORD)
    assert result.returncode == ExitCode.OK, result.stderr
    stem = name.rsplit(".", 1)[0]
    assert (tmp_path / f"{stem}-unprotected.pdf").exists()


@pytest.mark.parametrize("name", AWKWARD_NAMES)
@pytest.mark.parametrize("encoding", ["cp1252", "ascii"])
def test_a_console_that_cannot_print_the_name_does_not_crash(
    fpr, tmp_path: Path, name: str, encoding: str
) -> None:
    """What a Windows console gives a redirected `fpr ... > log.txt`.

    Python encodes a redirected stream in the ANSI code page there, which cannot
    represent most of the world's file names. Printing one must degrade, never
    raise: the output file already exists by the time its name is printed, and
    a crash at that point reports failure for work that succeeded.
    """
    (tmp_path / name).write_bytes(F.make_pdf(F.PdfSpec(user=SAMPLE_PASSWORD, owner=OWNER_PASSWORD)))
    env = {"PYTHONIOENCODING": encoding}
    assert fpr("inspect", name, env=env).returncode == ExitCode.OK
    result = fpr("remove", name, "--password-stdin", stdin=SAMPLE_PASSWORD, env=env)
    assert result.returncode == ExitCode.OK, result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("name", AWKWARD_NAMES)
def test_a_generated_password_is_shown_even_when_the_name_cannot_be(
    fpr, tmp_path: Path, name: str
) -> None:
    """The failure this whole feature is designed around.

    If the report crashes before the password line, the file is encrypted with
    a password nobody has ever seen, and this tool refuses to crack it back
    open. It must not be possible for a file name to cause that.
    """
    (tmp_path / name).write_bytes(F.make_pdf())
    result = fpr("protect", name, "--generate", env={"PYTHONIOENCODING": "cp1252"})
    assert result.returncode == ExitCode.OK, result.stderr
    stem = name.rsplit(".", 1)[0]
    protected = tmp_path / f"{stem}-protected.pdf"
    assert protected.exists()

    lines = [line.strip() for line in result.stdout.splitlines()]
    password = lines[lines.index("PASSWORD") + 1]
    reopened = fpr(
        "remove", protected.name, "--password-stdin", "-o", "reopened.pdf", stdin=password
    )
    assert reopened.returncode == ExitCode.OK, "the password shown does not open the file"


def test_version_flag_and_formats_run_without_a_file(fpr) -> None:
    assert fpr("--version").returncode == 0
    assert fpr("formats").returncode == ExitCode.OK
    assert fpr("version").returncode == ExitCode.OK
