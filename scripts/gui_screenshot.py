#!/usr/bin/env python3
"""Capture a screenshot of the desktop window, for release evidence.

Drives the real App class, loads a generated fixture so the window shows real
detection output, then captures the window region. macOS only today
(``screencapture``); on other platforms it prints how to do the equivalent.

    python scripts/gui_screenshot.py artifacts/gui-macos.png
"""

from __future__ import annotations

import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fpr.testing import fixtures as F  # noqa: E402
from fpr_gui.app import App  # noqa: E402


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    completed = "--completed" in sys.argv
    protected = "--protected" in sys.argv
    target = Path(args[0] if args else "artifacts/gui.png")
    target.parent.mkdir(parents=True, exist_ok=True)

    sample_dir = target.parent / "gui-sample"
    sample_dir.mkdir(exist_ok=True)
    sample = sample_dir / "quarterly-report.pdf"
    for stale in list(sample_dir.glob("*-unprotected.pdf")) + list(
        sample_dir.glob("*-protected.pdf")
    ):
        stale.unlink()
    # The protect shot needs a file with nothing on it yet; the others need one
    # that is actually locked.
    sample.write_bytes(
        F.make_pdf(F.PdfSpec(pages=12))
        if protected
        else F.make_pdf(F.PdfSpec(pages=12, user="screenshot-demo", owner="screenshot-owner"))
    )

    root = tk.Tk()
    app = App(root)
    app.load(sample)

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and app.busy:
        root.update()
        time.sleep(0.02)

    if protected:
        # Drive a real protect run, so the generated password on screen is one
        # the tool actually produced and the hallmark row is real evidence.
        app.generate_var.set(True)
        app.on_run()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and app.busy:
            root.update()
            time.sleep(0.02)

    if completed:
        # Drive a real removal so the window shows the verification evidence
        # rather than a mocked-up success message.
        app.password_var.set("screenshot-demo")
        app.on_run()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and app.busy:
            root.update()
            time.sleep(0.02)

    root.deiconify()
    root.lift()
    root.attributes("-topmost", True)
    for _ in range(40):
        root.update()
        time.sleep(0.02)

    geometry = (root.winfo_rootx(), root.winfo_rooty(), root.winfo_width(), root.winfo_height())
    print(f"window at x={geometry[0]} y={geometry[1]} {geometry[2]}x{geometry[3]}")

    if sys.platform == "darwin":
        # screencapture rejects negative origins, and Tk can place a window a
        # few pixels off-screen; clamp rather than fail.
        x = max(0, geometry[0] - 8)
        y = max(0, geometry[1] - 30)
        region = f"{x},{y},{geometry[2] + 16},{geometry[3] + 34}"
        subprocess.run(["/usr/sbin/screencapture", "-x", "-R", region, str(target)], check=True)
        print(f"wrote {target}")
    else:
        print("screenshot capture is implemented for macOS only; use your OS tool on the window")

    app.stop()
    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
