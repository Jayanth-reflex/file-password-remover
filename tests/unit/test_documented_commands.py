"""Every `fpr` command printed in the docs must actually parse.

A worked example that errors is worse than no example: it is followed
verbatim, fails with a usage error, and the reader assumes the tool is broken.
This caught `fpr remove ... --json`, which was shipped in the README, the
website and the agent guide -- `--json` is a global flag and has to precede the
subcommand, so every one of those examples exited 2.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from fpr.cli.main import build_parser

ROOT = Path(__file__).resolve().parent.parent.parent

# Files whose fenced shell blocks are shown to users as things to run.
DOC_SOURCES = [
    "README.md",
    "docs/ops/cli.md",
    "site/agents.md",
    "site/index.html",
]

# Placeholders that stand in for a real path or value in documentation.
_PLACEHOLDER = re.compile(r"[$<>{}*~]|\.\.\.|PASSWORD|FILE|DIR")


def _commands() -> list[tuple[str, str]]:
    """Every `fpr ...` invocation appearing in the documentation."""
    found: list[tuple[str, str]] = []
    for relative in DOC_SOURCES:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for raw in re.findall(r"(?:^|\||\$ )\s*(fpr(?:-gui)? [^\n<|&]*)", text, re.MULTILINE):
            command = raw.split("#", 1)[0].strip().rstrip("\\").strip()
            # Multi-line continuations and shell pipelines are out of scope:
            # this checks argument *shape*, not shell syntax.
            if not command or command.startswith("fpr-gui"):
                continue
            # "fpr [--json] [-v|-q] COMMAND" is a usage synopsis, not a command.
            if "[" in command:
                continue
            # A trailing bare integer is the file-descriptor number of a shell
            # redirect ("--password-fd 3 3< file"), not an argument.
            parts = command.split()
            if len(parts) > 1 and parts[-1].isdigit() and not parts[-2].startswith("--"):
                command = " ".join(parts[:-1])
            found.append((relative, command))
    return found


DOCUMENTED = _commands()


def test_the_docs_actually_contain_commands_to_check() -> None:
    """Guards against the extraction silently matching nothing."""
    assert len(DOCUMENTED) >= 10, f"only found {len(DOCUMENTED)} commands"


@pytest.mark.parametrize(
    ("source", "command"),
    DOCUMENTED,
    ids=[f"{source}:{command[:60]}" for source, command in DOCUMENTED],
)
def test_documented_command_parses(source: str, command: str) -> None:
    try:
        argv = shlex.split(command)[1:]
    except ValueError:
        pytest.skip(f"not a single shell word list: {command}")

    # Replace documentation placeholders with something concrete, so the parse
    # checks flag placement rather than whether a sample path exists.
    argv = ["placeholder.pdf" if _PLACEHOLDER.search(part) else part for part in argv]

    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exit_error:  # argparse exits 2 on a usage error
        pytest.fail(
            f"{source} documents a command that does not parse "
            f"(exit {exit_error.code}): fpr {' '.join(argv)}"
        )
