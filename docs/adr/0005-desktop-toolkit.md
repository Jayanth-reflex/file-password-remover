# ADR-0005: Tkinter for the desktop window

**Status**: Accepted · **Date**: 2026-09-19 · **Owner**: Architecture / Product

## Context

The desktop app needs: a file chooser, a password field, two checkboxes, a
button, and a status area. It must run on macOS, Windows and Linux, and it
must not undermine the project's small, auditable dependency set.

## Decision

Tkinter/ttk from the standard library.

## Alternatives considered

| Option | Why not |
| --- | --- |
| **PySide6 / Qt** | LGPL-3 with real bundling obligations, ~150 MB in the bundle, and a large dependency to audit — for four controls. Genuinely better-looking. |
| **wxPython** | Native look, but heavy to build and a thinner maintenance story. |
| **Electron / Tauri** | A browser engine and a second language runtime to open a local file. Tauri is lighter but still adds Rust plus a webview. |
| **Kivy / BeeWare Toga** | Toga is interesting for the shared mobile story ([ADR-0010](0010-no-mobile-app-this-release.md)); as of this release it is less mature on desktop than Tk. |
| **CLI only** | Rejected: the people most at risk of pasting a confidential file into a website are exactly the ones who will not use a terminal. |

## What it costs us, stated plainly

- **No drag-and-drop.** Tk needs the external `tkdnd` package. The window has a
  file chooser instead, and the docs do not pretend otherwise.
- **Plain visuals.** `aqua` on macOS and `vista` on Windows look native enough;
  Linux gets `clam`.
- **Accessibility depends on the platform Tk build.** Tk has no ARIA
  equivalent. We guarantee what we can test — full keyboard operability, a
  visible label on every control, status conveyed as words rather than colour —
  and we say what we cannot verify in
  [accessibility.md](../product/accessibility.md).
- **Threading discipline is on us.** Tk is not thread-safe, so work runs on a
  worker thread and results come back through a `queue.Queue` that the Tk
  thread polls.

## Consequences

*Good*: zero additional dependencies, a bundle measured in tens of megabytes,
nothing new in the supply chain, and a window that starts instantly.

*Bad*: the app looks like a utility, because it is one.

## Reversal cost

Low. `src/fpr_gui/` is a thin shell over `fpr.engine`; a different toolkit
would reimplement the same ~250 lines against the same API.
