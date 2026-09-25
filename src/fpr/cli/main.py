"""``fpr`` -- the command line entry point.

    fpr inspect FILE...                 what protection does this carry?
    fpr remove  FILE... [options]       write a verified unprotected copy
    fpr formats                         what is supported, and what is not
    fpr version                         version and dependency provenance

Exit codes are stable and documented in :class:`fpr.errors.ExitCode`; see also
docs/ops/cli.md. Anything other than 0 means nothing was written.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .. import __version__, passwords
from ..batch import collect_inputs, run_batch
from ..engine import (
    DEFAULT_SUFFIX,
    PROTECTED_SUFFIX,
    ProtectOptions,
    RemovalOptions,
    inspect,
    protect,
    remove,
)
from ..errors import ExitCode, FprError, UsageError
from ..logging_setup import configure
from ..policy import POLICY_RULES
from ..registry import UNSUPPORTED_BY_DESIGN, known_formats
from ..secret import Secret
from .output import Renderer
from .password_input import add_password_arguments, resolve_secret

__all__ = ["main", "build_parser"]

_EPILOG = """\
examples:
  fpr inspect report.pdf
  fpr remove report.pdf                         # writes report-unprotected.pdf
  fpr remove report.pdf -o ~/Desktop/clean.pdf
  fpr remove *.docx --output-dir ./clean
  printf '%s' "$PW" | fpr remove book.pdf --password-stdin
  fpr remove ./archive --recursive --pattern '*.zip' --json

This tool removes protection only from files you can already unlock. It does
not recover, guess or crack passwords, and it will refuse to strip permission
flags from a document you cannot authenticate against.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fpr",
        description="Remove password protection from files you own, locally.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"fpr {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Repeat for more detail."
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print errors.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_inspect = sub.add_parser(
        "inspect",
        help="Report what protection a file carries. Never asks for a password.",
        description="Identify files by content and describe their protection. No password needed.",
    )
    p_inspect.add_argument("paths", nargs="+", type=Path, metavar="FILE")
    p_inspect.add_argument(
        "-r", "--recursive", action="store_true", help="Descend into directories."
    )
    p_inspect.add_argument(
        "--pattern",
        action="append",
        default=None,
        metavar="GLOB",
        help="Filter directory contents (repeatable). Default: *",
    )

    p_remove = sub.add_parser(
        "remove",
        help="Write a verified, unprotected copy.",
        description=(
            "Decrypt a file with the password you supply and write an unprotected copy. "
            "The original is never modified unless --in-place is given."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p_remove.add_argument("paths", nargs="+", type=Path, metavar="FILE")
    out = p_remove.add_argument_group("output")
    out.add_argument("-o", "--output", type=Path, help="Exact output path (single input only).")
    out.add_argument("--output-dir", type=Path, help="Directory for the unprotected copies.")
    out.add_argument(
        "--suffix",
        default=DEFAULT_SUFFIX,
        help=f"Suffix added to the stem of the output name (default: {DEFAULT_SUFFIX}).",
    )
    out.add_argument("--overwrite", action="store_true", help="Replace an existing output file.")
    out.add_argument(
        "--in-place",
        action="store_true",
        help="Replace the original file with the unprotected copy. Off by default, on purpose.",
    )
    out.add_argument(
        "--no-preserve-timestamps",
        dest="preserve_timestamps",
        action="store_false",
        help="Do not copy the original's modification time onto the output.",
    )
    behave = p_remove.add_argument_group("behaviour")
    behave.add_argument(
        "--remove-restrictions",
        action="store_true",
        help="Also clear permission/owner restrictions. Requires the owner password.",
    )
    behave.add_argument(
        "--experimental",
        action="store_true",
        help="Enable format support that has no automated test coverage.",
    )
    behave.add_argument("-r", "--recursive", action="store_true", help="Descend into directories.")
    behave.add_argument(
        "--pattern",
        action="append",
        default=None,
        metavar="GLOB",
        help="Filter directory contents (repeatable). Default: *",
    )
    behave.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Abort a batch at the first failure instead of continuing.",
    )
    add_password_arguments(p_remove)

    p_protect = sub.add_parser(
        "protect",
        help="Write a verified, password-protected copy.",
        description=(
            "Encrypt a file with a password you supply or one generated for you, and write "
            "a protected copy. The original is never modified, and there is no --in-place: "
            "if the only copy of the password were lost, the file would be unrecoverable, "
            "and this tool refuses to crack it back open."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p_protect.add_argument("paths", nargs="+", type=Path, metavar="FILE")
    pout = p_protect.add_argument_group("output")
    pout.add_argument("-o", "--output", type=Path, help="Exact output path (single input only).")
    pout.add_argument("--output-dir", type=Path, help="Directory for the protected copies.")
    pout.add_argument(
        "--suffix",
        default=PROTECTED_SUFFIX,
        help=f"Suffix added to the stem of the output name (default: {PROTECTED_SUFFIX}).",
    )
    pout.add_argument("--overwrite", action="store_true", help="Replace an existing output file.")
    pout.add_argument(
        "--no-preserve-timestamps",
        dest="preserve_timestamps",
        action="store_false",
        help="Do not copy the original's modification time onto the output.",
    )
    pw = p_protect.add_argument_group("password")
    pw.add_argument(
        "--generate",
        action="store_true",
        help="Generate a strong password instead of asking for one. It is printed once: "
        "this tool cannot recover it later.",
    )
    pw.add_argument(
        "--password-out",
        type=Path,
        metavar="FILE",
        help="Write a generated password to FILE instead of printing it, which keeps it "
        "out of terminal scrollback. Created owner-only (0600) on macOS and Linux; on "
        "Windows it inherits the directory's permissions, so choose the directory "
        "accordingly.",
    )
    add_password_arguments(p_protect)

    sub.add_parser(
        "formats",
        help="List supported formats, protections and deliberate exclusions.",
        description="Everything the tool can and will not do, with reasons.",
    )
    sub.add_parser("version", help="Print version and dependency provenance.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure(args.verbose)
    renderer = Renderer(as_json=args.json, quiet=args.quiet)

    if args.command is None:
        # The menu, not an argparse dump. `fpr --help` still prints the full
        # listing; a bare `fpr` is somebody arriving, and the first screen has
        # to answer "what will this do to my file?" rather than enumerate flags.
        # The exit code stays USAGE: no command ran, and scripts that branch on
        # it were written against that.
        renderer.menu()
        return int(ExitCode.USAGE)

    try:
        if args.command == "inspect":
            return _cmd_inspect(args, renderer)
        if args.command == "remove":
            return _cmd_remove(args, renderer)
        if args.command == "protect":
            return _cmd_protect(args, renderer)
        if args.command == "formats":
            return _cmd_formats(renderer)
        if args.command == "version":
            return _cmd_version(renderer)
    except FprError as exc:
        renderer.error(exc.message, exc.remediation, code=type(exc).__name__)
        return int(exc.exit_code)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        renderer.error("Interrupted. Nothing was written.")
        return int(ExitCode.INTERRUPTED)
    return int(ExitCode.USAGE)  # pragma: no cover - argparse covers this


def _patterns(args: argparse.Namespace) -> list[str]:
    return args.pattern or ["*"]


def _cmd_inspect(args: argparse.Namespace, renderer: Renderer) -> int:
    paths = collect_inputs(args.paths, recursive=args.recursive, patterns=_patterns(args))
    if not paths:
        raise UsageError("No input files matched.")
    payloads = []
    worst = ExitCode.OK
    for path in paths:
        try:
            detection = inspect(path)
        except FprError as exc:
            if args.json:
                payloads.append(
                    {
                        "ok": False,
                        "path": str(path),
                        "error": type(exc).__name__,
                        "message": exc.message,
                    }
                )
            else:
                renderer.error(f"{path}: {exc.message}", exc.remediation)
            worst = exc.exit_code
            continue
        if args.json:
            from .output import _detection_payload

            payloads.append(_detection_payload(detection))
        else:
            renderer.detection(detection)
            renderer.line()
    if args.json:
        renderer.json({"ok": worst == ExitCode.OK, "results": payloads})
    return int(worst)


def _cmd_remove(args: argparse.Namespace, renderer: Renderer) -> int:
    paths = collect_inputs(args.paths, recursive=args.recursive, patterns=_patterns(args))
    if not paths:
        raise UsageError("No input files matched.")
    if args.output is not None and len(paths) > 1:
        raise UsageError(
            f"--output names a single file but {len(paths)} inputs matched.",
            remediation="Use --output-dir for more than one file.",
        )
    if args.in_place and (args.output or args.output_dir):
        raise UsageError("--in-place cannot be combined with --output or --output-dir.")

    options = RemovalOptions(
        output=args.output,
        output_dir=args.output_dir,
        suffix=args.suffix,
        overwrite=args.overwrite,
        in_place=args.in_place,
        allow_restriction_removal=args.remove_restrictions,
        experimental=args.experimental,
        preserve_timestamps=args.preserve_timestamps,
    )
    if options.output_dir is not None:
        options.output_dir.mkdir(parents=True, exist_ok=True)

    with resolve_secret(args) as secret:
        if len(paths) == 1:
            result = remove(paths[0], secret, options)
            renderer.result(result)
            return int(ExitCode.OK)

        def progress(index: int, total: int, path: Path) -> None:
            if not args.quiet and not args.json:
                print(f"[{index}/{total}] {path.name}", file=sys.stderr)

        report = run_batch(
            paths, secret, options, on_progress=progress, stop_on_error=args.stop_on_error
        )
    renderer.batch(report)
    return int(ExitCode.PARTIAL_FAILURE if report.failed else ExitCode.OK)


def _cmd_protect(args: argparse.Namespace, renderer: Renderer) -> int:
    paths = collect_inputs(args.paths, recursive=False, patterns=[])
    if not paths:
        raise UsageError("No input files matched.")
    if len(paths) > 1:
        raise UsageError(
            f"protect takes one file at a time, but {len(paths)} matched.",
            remediation="Protecting a batch would produce a set of passwords to keep track "
            "of in one go, which is how people lose them. Run it per file.",
        )
    if args.generate and (args.password_stdin or args.password_file or args.password_fd):
        raise UsageError("--generate cannot be combined with a supplied password.")

    options = ProtectOptions(
        output=args.output,
        output_dir=args.output_dir,
        suffix=args.suffix,
        overwrite=args.overwrite,
        preserve_timestamps=args.preserve_timestamps,
    )
    if options.output_dir is not None:
        options.output_dir.mkdir(parents=True, exist_ok=True)

    if args.generate:
        secret = passwords.generate()
    else:
        # confirm=True makes the user type it twice: a typo here is not
        # recoverable, because the file will only open with what was typed.
        secret = resolve_secret(args, confirm=True)

    with secret:
        result = protect(paths[0], secret, options)
        # The password is surfaced *after* the file exists, so a crash between
        # the two cannot leave a locked file whose password was never shown.
        written_to: Path | None = None
        if args.generate and args.password_out is not None:
            written_to = _write_password(args.password_out, secret)
        renderer.protected(
            result,
            generated=secret if args.generate and written_to is None else None,
            password_file=written_to,
        )
    return int(ExitCode.OK)


def _write_password(path: Path, secret: Secret) -> Path:
    """Write a generated password to a file only its owner can read."""
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream, secret.expose() as text:
        stream.write(text + "\n")
    return path


def _cmd_formats(renderer: Renderer) -> int:
    rows = known_formats()
    if renderer.as_json:
        renderer.json(
            {
                "supported": rows,
                "unsupported_by_design": [
                    {"what": what, "why": why} for what, why in UNSUPPORTED_BY_DESIGN
                ],
                "policy": [{"id": i, "rule": r} for i, r in POLICY_RULES],
            }
        )
        return int(ExitCode.OK)
    renderer.line("Supported formats")
    for row in rows:
        # Say which direction each format works in: removing protection is
        # supported everywhere, adding it is not, and guessing wrong about that
        # is how someone ends up with an unencrypted copy they thought was safe.
        directions = "remove" + (" + protect" if row["can_protect"] == "yes" else "")
        renderer.line(f"  {row['id']:<14} {row['name']}  ({directions})")
        renderer.line(f"  {'':<14} {row['extensions']}")
    renderer.line()
    renderer.line("Not supported, by design")
    for what, why in UNSUPPORTED_BY_DESIGN:
        renderer.line(f"  {what}")
        renderer.line(f"      {why}")
    renderer.line()
    renderer.line("Policy")
    for ident, rule in POLICY_RULES:
        renderer.line(f"  {ident}  {rule}")
    return int(ExitCode.OK)


def _cmd_version(renderer: Renderer) -> int:
    import platform

    info = {
        "fpr": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }
    for module, label in (
        ("pikepdf", "pikepdf"),
        ("msoffcrypto", "msoffcrypto-tool"),
        ("pyzipper", "pyzipper"),
        ("py7zr", "py7zr (optional)"),
    ):
        info[label] = _module_version(module)
    try:
        import pikepdf

        info["libqpdf"] = pikepdf.__libqpdf_version__
    except Exception:  # noqa: BLE001 - an optional provenance detail
        info["libqpdf"] = "unknown"
    if renderer.as_json:
        renderer.json(info)
        return int(ExitCode.OK)
    for key, value in info.items():
        renderer.line(f"{key:<20} {value}")
    return int(ExitCode.OK)


def _module_version(name: str) -> str:
    try:
        import importlib.metadata as md

        mapping = {"msoffcrypto": "msoffcrypto-tool"}
        return md.version(mapping.get(name, name))
    except Exception:  # noqa: BLE001
        return "not installed"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
