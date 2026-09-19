# PyInstaller spec for the File Password Remover bundle.
#
# One bundle containing both entry points:
#   fpr      the command line
#   fpr-gui  the desktop window
#
# Two things here are load-bearing and easy to break:
#
# 1. `copy_metadata` for the runtime dependencies. `fpr version` reports
#    dependency provenance through importlib.metadata, and pikepdf's wheel
#    carries the IJG licence text that libjpeg-turbo's terms require to
#    accompany redistribution. Dropping the metadata directories would both
#    break the command and create a licence problem.
#
# 2. `excludes` keeps py7zr out. It is LGPL-2.1-or-later and deliberately not
#    bundled -- see docs/adr/0006-optional-lgpl-sevenzip-extra.md. If you add
#    it here you take on a relinking obligation for every binary you ship.

from PyInstaller.utils.hooks import copy_metadata, collect_submodules

metadata = []
for dist in ("pikepdf", "msoffcrypto-tool", "pyzipper", "cryptography", "olefile", "lxml"):
    try:
        metadata += copy_metadata(dist)
    except Exception:  # noqa: BLE001 - an absent optional dependency is not fatal
        pass

hidden = collect_submodules("fpr") + collect_submodules("fpr_gui")

cli = Analysis(
    ["entry_cli.py"],
    pathex=["../../src"],
    binaries=[],
    datas=metadata + [("../../src/fpr/locales", "fpr/locales")],
    hiddenimports=hidden,
    excludes=["py7zr", "tkinter.test", "test", "unittest", "pydoc_data"],
    noarchive=False,
)

gui = Analysis(
    ["entry_gui.py"],
    pathex=["../../src"],
    binaries=[],
    datas=metadata + [("../../src/fpr/locales", "fpr/locales")],
    hiddenimports=hidden,
    excludes=["py7zr", "test", "unittest", "pydoc_data"],
    noarchive=False,
)

MERGE((cli, "fpr", "fpr"), (gui, "fpr-gui", "fpr-gui"))

cli_pyz = PYZ(cli.pure, cli.zipped_data)
cli_exe = EXE(
    cli_pyz, cli.scripts, [], exclude_binaries=True,
    name="fpr", console=True, strip=False, upx=False,
)

gui_pyz = PYZ(gui.pure, gui.zipped_data)
gui_exe = EXE(
    gui_pyz, gui.scripts, [], exclude_binaries=True,
    name="fpr-gui", console=False, strip=False, upx=False,
)

COLLECT(
    cli_exe, cli.binaries, cli.zipfiles, cli.datas,
    gui_exe, gui.binaries, gui.zipfiles, gui.datas,
    strip=False, upx=False, name="file-password-remover",
)
