"""The ``protect`` command, from the outside.

The generated-password path is the security-critical one: the tool refuses to
crack, so a password it generates and fails to show is a file destroyed.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path

from fpr.cli.main import main
from fpr.errors import ExitCode

PASSWORD_PATTERN = re.compile(r"[a-z0-9]{4}(?:-[a-z0-9]{4}){4}")


def test_generate_prints_the_password_and_locks_the_file(pdf_plain: Path, capsys) -> None:
    code = main(["protect", str(pdf_plain), "--generate"])
    out = capsys.readouterr().out

    assert code == ExitCode.OK
    match = PASSWORD_PATTERN.search(out)
    assert match, f"the generated password was never shown:\n{out}"

    protected = pdf_plain.parent / "plain-protected.pdf"
    assert protected.exists()

    # The password that was shown must be the one that opens it. This is the
    # whole contract: anything else means the file is gone.
    code = main(
        [
            "remove",
            str(protected),
            "--output",
            str(pdf_plain.parent / "back.pdf"),
            "--password-file",
            str(_write(pdf_plain.parent / "pw", match.group(0))),
        ]
    )
    assert code == ExitCode.OK


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def test_password_out_writes_owner_only_and_keeps_it_off_the_screen(
    pdf_plain: Path, tmp_path: Path, capsys
) -> None:
    target = tmp_path / "key.txt"

    code = main(["protect", str(pdf_plain), "--generate", "--password-out", str(target)])
    out = capsys.readouterr().out

    assert code == ExitCode.OK
    assert not PASSWORD_PATTERN.search(out), "the password was printed as well as written"

    written = target.read_text().strip()
    assert PASSWORD_PATTERN.fullmatch(written)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"password file is {oct(mode)}, not owner-only"


def test_json_returns_the_generated_password_so_a_caller_can_keep_it(
    pdf_plain: Path, capsys
) -> None:
    """An agent that cannot read the password back has destroyed the file."""
    code = main(["--json", "protect", str(pdf_plain), "--generate"])

    assert code == ExitCode.OK
    payload = json.loads(capsys.readouterr().out)
    assert PASSWORD_PATTERN.fullmatch(payload["generated_password"])
    assert payload["verification"]["encrypted"] == "true"


def test_a_supplied_password_is_never_echoed(pdf_plain: Path, tmp_path: Path, capsys) -> None:
    pwfile = _write(tmp_path / "pw", "a-password-i-chose")

    code = main(["protect", str(pdf_plain), "--password-file", str(pwfile)])
    out = capsys.readouterr().out

    assert code == ExitCode.OK
    assert "a-password-i-chose" not in out, "the user's own password was echoed back"


def test_generate_cannot_be_combined_with_a_supplied_password(
    pdf_plain: Path, tmp_path: Path
) -> None:
    pwfile = _write(tmp_path / "pw", "something")
    assert main(["protect", str(pdf_plain), "--generate", "--password-file", str(pwfile)]) == (
        ExitCode.USAGE
    )


def test_protecting_many_files_at_once_is_refused(pdf_plain: Path, zip_plain: Path) -> None:
    """A batch of generated passwords is how people lose them."""
    assert main(["protect", str(pdf_plain), str(zip_plain), "--generate"]) == ExitCode.USAGE
