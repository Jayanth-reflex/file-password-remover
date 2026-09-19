"""The desktop application.

Tkinter, deliberately. It ships with CPython on all three desktop platforms,
which means the app has no GUI dependency to audit, no Chromium to bundle, and
a download measured in megabytes rather than hundreds of them. The trade-off is
a plain-looking window and no drag-and-drop (Tk needs the external ``tkdnd``
package for that) -- both recorded in docs/adr/0005-desktop-toolkit.md.

The window is a thin shell over :mod:`fpr.engine`. It cannot do anything the
CLI cannot, it enforces the same policy, and it shows the same verification
evidence. Long operations run on a worker thread so the window keeps
repainting; all widget updates are marshalled back to the Tk thread through a
queue, because Tk is not thread-safe.

Accessibility notes are in docs/product/accessibility.md. In short: every
control is reachable and operable from the keyboard, every field has a visible
label, the status line is a single element that is rewritten (so assistive
technology that polls it sees one changing string), and nothing depends on
colour alone.
"""

from __future__ import annotations

import contextlib
import os
import queue

# Used only to reveal a finished file in the platform file manager.
import subprocess  # noqa: S404  # nosec B404
import sys
import threading
import tkinter as tk
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from fpr import RemovalOptions, Secret, __version__, inspect, plan_output_path, remove
from fpr.errors import FprError
from fpr.i18n import t
from fpr.types import Detection, Removability, RemovalResult

__all__ = ["main", "App"]

PAD = 12


@dataclass
class _Message:
    kind: str
    payload: Any


class App:
    """The main window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.queue: queue.Queue[_Message] = queue.Queue()
        self.source: Path | None = None
        self.detection: Detection | None = None
        self.output: Path | None = None
        self.busy = False
        self._poll_job: str | None = None

        root.title(t("gui.title", "File Password Remover"))
        root.minsize(620, 520)
        self._build()
        self._poll_queue()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        style = ttk.Style()
        if "aqua" in style.theme_names() and sys.platform == "darwin":
            style.theme_use("aqua")

        outer = ttk.Frame(self.root, padding=PAD)
        outer.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        heading = ttk.Label(
            outer, text=t("gui.title", "File Password Remover"), font=("TkDefaultFont", 16, "bold")
        )
        heading.grid(row=0, column=0, sticky="w")
        ttk.Label(
            outer,
            text=t(
                "gui.subtitle",
                "Remove protection from a file you have the password for. "
                "Everything happens on this computer.",
            ),
            wraplength=560,
            justify="left",
        ).grid(row=1, column=0, sticky="w", pady=(2, PAD))

        # ---- file picker
        filebox = ttk.LabelFrame(outer, text="1. " + t("gui.choose", "Choose file…"), padding=PAD)
        filebox.grid(row=2, column=0, sticky="ew")
        filebox.columnconfigure(1, weight=1)
        self.choose_button = ttk.Button(
            filebox, text=t("gui.choose", "Choose file…"), command=self.on_choose
        )
        self.choose_button.grid(row=0, column=0, sticky="w")
        self.file_label = ttk.Label(
            filebox, text=t("gui.file.none", "No file chosen."), wraplength=380, justify="left"
        )
        self.file_label.grid(row=0, column=1, sticky="w", padx=(PAD, 0))

        self.detail = tk.Text(
            filebox, height=5, wrap="word", borderwidth=0, highlightthickness=0, takefocus=True
        )
        self.detail.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(PAD, 0))
        self.detail.configure(state="disabled", background=self.root.cget("background"))

        # ---- password
        pwbox = ttk.LabelFrame(outer, text="2. " + t("gui.password", "Password"), padding=PAD)
        pwbox.grid(row=3, column=0, sticky="ew", pady=(PAD, 0))
        pwbox.columnconfigure(1, weight=1)
        ttk.Label(pwbox, text=t("gui.password", "Password") + ":").grid(row=0, column=0, sticky="w")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pwbox, textvariable=self.password_var, show="•")
        self.password_entry.grid(row=0, column=1, sticky="ew", padx=(PAD, 0))
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            pwbox,
            text=t("gui.password.show", "Show password"),
            variable=self.show_var,
            command=self._toggle_password,
        ).grid(row=1, column=1, sticky="w", padx=(PAD, 0), pady=(6, 0))

        # ---- output
        outbox = ttk.LabelFrame(
            outer, text="3. " + t("gui.output", "Save the unprotected copy to"), padding=PAD
        )
        outbox.grid(row=4, column=0, sticky="ew", pady=(PAD, 0))
        outbox.columnconfigure(0, weight=1)
        self.output_label = ttk.Label(outbox, text="—", wraplength=420, justify="left")
        self.output_label.grid(row=0, column=0, sticky="w")
        ttk.Button(
            outbox, text=t("gui.output.choose", "Change…"), command=self.on_choose_output
        ).grid(row=0, column=1, sticky="e")
        self.overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            outbox,
            text=t("gui.overwrite", "Replace the file if it already exists"),
            variable=self.overwrite_var,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.restrictions_var = tk.BooleanVar(value=False)
        self.restrictions_check = ttk.Checkbutton(
            outbox,
            text=t(
                "gui.restrictions",
                "Also remove permission restrictions (needs the owner password)",
            ),
            variable=self.restrictions_var,
            state="disabled",
        )
        self.restrictions_check.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # ---- action
        actions = ttk.Frame(outer)
        actions.grid(row=5, column=0, sticky="ew", pady=(PAD, 0))
        actions.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(actions, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, PAD))
        self.run_button = ttk.Button(
            actions,
            text=t("gui.remove", "Remove protection"),
            command=self.on_run,
            default="active",
        )
        self.run_button.grid(row=0, column=1, sticky="e")
        self.reveal_button = ttk.Button(
            actions,
            text=t("gui.reveal", "Show in folder"),
            command=self.on_reveal,
            state="disabled",
        )
        self.reveal_button.grid(row=0, column=2, sticky="e", padx=(6, 0))

        # ---- status line (a single element, rewritten in place)
        self.status = ttk.Label(
            outer, text=t("gui.status.ready", "Ready."), wraplength=560, justify="left"
        )
        self.status.grid(row=6, column=0, sticky="w", pady=(PAD, 0))

        ttk.Label(
            outer,
            text=t(
                "gui.about.body",
                "File Password Remover {version}. No network access, no telemetry. "
                "Licensed under Apache-2.0.",
                version=__version__,
            ),
            foreground="#666666",
        ).grid(row=7, column=0, sticky="w", pady=(PAD, 0))

        self.root.bind("<Return>", lambda _event: self.on_run())
        self.root.bind("<Escape>", lambda _event: self.root.focus_set())
        self.choose_button.focus_set()

    def _toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_var.get() else "•")

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    # -------------------------------------------------------------- actions
    def on_choose(self) -> None:
        chosen = filedialog.askopenfilename(
            title=t("gui.choose.hint", "Pick a protected PDF, Office document or archive."),
            filetypes=[
                ("Supported files", "*.pdf *.docx *.xlsx *.pptx *.doc *.xls *.ppt *.zip *.7z"),
                ("All files", "*.*"),
            ],
        )
        if not chosen:
            return
        self.load(Path(chosen))

    def load(self, path: Path) -> None:
        """Select ``path`` and inspect it on a worker thread."""
        self.source = path
        self.file_label.configure(text=str(path))
        self.output = None
        self.reveal_button.grid_remove()
        self._set_detail(t("gui.inspecting", "Inspecting…"))
        self._run_async(lambda: inspect(path), "detection")

    def on_choose_output(self) -> None:
        if self.source is None:
            messagebox.showinfo(
                t("gui.title", "File Password Remover"), t("gui.nofile", "Choose a file first.")
            )
            return
        suggested = plan_output_path(self.source, self._options())
        chosen = filedialog.asksaveasfilename(
            initialfile=suggested.name,
            initialdir=str(suggested.parent),
            defaultextension=self.source.suffix,
        )
        if chosen:
            self.output = Path(chosen)
            self.output_label.configure(text=str(self.output))

    def _options(self) -> RemovalOptions:
        return RemovalOptions(
            output=self.output,
            overwrite=self.overwrite_var.get(),
            allow_restriction_removal=self.restrictions_var.get(),
        )

    def on_run(self) -> None:
        if self.busy:
            return
        if self.source is None:
            messagebox.showinfo(
                t("gui.title", "File Password Remover"), t("gui.nofile", "Choose a file first.")
            )
            return
        if not self.password_var.get():
            messagebox.showinfo(
                t("gui.title", "File Password Remover"),
                t("gui.password.empty", "Enter the file's password first."),
            )
            self.password_entry.focus_set()
            return

        source = self.source
        options = self._options()
        # Take the password out of the Tk variable immediately: a StringVar
        # lives as long as the widget, and we do not want it to.
        secret = Secret.from_text(self.password_var.get())
        self.password_var.set("")

        def work() -> RemovalResult:
            try:
                return remove(source, secret, options)
            finally:
                secret.close()

        self._set_status(t("gui.working", "Working…"))
        self._run_async(work, "result")

    def on_reveal(self) -> None:
        if self.output is None:
            return
        reveal_in_file_manager(self.output)

    # ------------------------------------------------------------- threading
    def _run_async(self, work: Callable[[], Any], kind: str) -> None:
        self.busy = True
        self.run_button.configure(state="disabled")
        self.choose_button.configure(state="disabled")
        self.progress.start(12)

        def runner() -> None:
            try:
                self.queue.put(_Message(kind, work()))
            except FprError as exc:
                self.queue.put(_Message("error", exc))
            except Exception as exc:  # noqa: BLE001 - surface, never swallow
                self.queue.put(_Message("error", exc))

        threading.Thread(target=runner, daemon=True, name=f"fpr-{kind}").start()

    def _poll_queue(self) -> None:
        try:
            while True:
                message = self.queue.get_nowait()
                self._handle(message)
        except queue.Empty:
            pass
        self._poll_job = self.root.after(80, self._poll_queue)

    def stop(self) -> None:
        """Cancel the queue poller.

        Without this the ``after`` chain keeps rescheduling itself for as long
        as the interpreter lives, which leaks a timer per window and makes the
        GUI tests pile up pollers on a shared root.
        """
        if self._poll_job is not None:
            with contextlib.suppress(tk.TclError):  # the root may already be gone
                self.root.after_cancel(self._poll_job)
            self._poll_job = None

    def _handle(self, message: _Message) -> None:
        self.busy = False
        self.progress.stop()
        self.run_button.configure(state="normal")
        self.choose_button.configure(state="normal")

        if message.kind == "detection":
            self.show_detection(message.payload)
        elif message.kind == "result":
            self.show_result(message.payload)
        elif message.kind == "error":
            self.show_error(message.payload)

    # -------------------------------------------------------------- display
    def show_detection(self, detection: Detection) -> None:
        self.detection = detection
        lines = [
            f"{t('gui.format', 'Format')}: {detection.format_name}",
            f"{t('gui.protection', 'Protection')}: {detection.protection.value}",
        ]
        if detection.algorithm:
            lines.append(f"{t('gui.algorithm', 'Algorithm')}: {detection.algorithm}")
        if detection.extension_mismatch:
            lines.append("! The file extension does not match its contents.")
        if detection.detail:
            lines.append(f"{t('gui.note', 'Note')}: {detection.detail}")
        self._set_detail("\n".join(lines))

        needs_flag = detection.removability is Removability.REMOVABLE_WITH_OWNER_PASSWORD
        self.restrictions_check.configure(state="normal" if needs_flag else "disabled")
        if not needs_flag:
            self.restrictions_var.set(False)
        self.run_button.configure(state="normal" if detection.actionable else "disabled")

        if self.source is not None:
            self.output_label.configure(text=str(plan_output_path(self.source, self._options())))
        self._set_status(t("gui.status.ready", "Ready."))

    def show_result(self, result: RemovalResult) -> None:
        self.output = result.output
        proof = ", ".join(f"{k}={v}" for k, v in result.verification.items())
        lines = [
            t(
                "gui.status.ok",
                "Done. Verified unprotected copy written to {path}.",
                path=str(result.output),
            ),
            t("gui.status.verified", "Verified: {proof}", proof=proof),
            t("gui.status.original", "The original file was not changed."),
        ]
        lines.extend(f"! {w}" for w in result.warnings)
        self._set_status("\n".join(lines))
        self.reveal_button.grid()

    def show_error(self, exc: BaseException) -> None:
        if isinstance(exc, FprError):
            body = exc.message + (f"\n\n{exc.remediation}" if exc.remediation else "")
        else:  # pragma: no cover - defensive
            body = f"{type(exc).__name__}: {exc}"
        self._set_status(body.splitlines()[0])
        messagebox.showerror(t("gui.error.title", "Could not remove the protection"), body)


def _file_manager_command(path: Path) -> list[str] | None:
    """Build the command that reveals ``path`` in the platform file manager.

    The executable is always an absolute path that this function chose.
    Invoking a bare ``explorer`` or ``xdg-open`` would resolve through ``PATH``,
    which anything running as this user can influence.

    ``platform`` is read into a local first: comparing ``sys.platform``
    directly makes a type checker prune the branches for other operating
    systems, which is not useful in code that has to run on all three.
    """
    platform = sys.platform
    if platform == "darwin":
        opener = Path("/usr/bin/open")
        return [str(opener), "-R", str(path)] if opener.exists() else None

    if platform.startswith("win"):
        # Windows environment variable names are case-insensitive, and so is
        # os.environ on Windows, so either spelling resolves.
        windir = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or "C:\\Windows"
        explorer = Path(windir) / "explorer.exe"
        return [str(explorer), f"/select,{path}"] if explorer.exists() else None

    for directory in ("/usr/bin", "/bin", "/usr/local/bin"):
        candidate = Path(directory) / "xdg-open"
        if candidate.exists():
            return [str(candidate), str(path.parent)]
    return None


def reveal_in_file_manager(path: Path) -> None:
    """Open the platform file manager with ``path`` selected.

    Best effort and non-fatal: a missing file manager is not a reason to fail a
    run that already succeeded.
    """
    command = _file_manager_command(path)
    if command is None:
        return
    # The executable is an absolute path this module chose, and the only
    # argument is a path the tool itself just wrote. No shell is involved.
    with contextlib.suppress(OSError):
        subprocess.run(command, check=False, shell=False)  # noqa: S603  # nosec B603


def main() -> int:
    root = tk.Tk()
    app = App(root)
    try:
        root.mainloop()
    finally:
        app.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
