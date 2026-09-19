# Accessibility

What is guaranteed, what is best effort, and what could not be verified on this
build host. The last category is the one most accessibility statements omit.

## Command line

The CLI is the most accessible interface this project has, and that is
deliberate rather than accidental.

| Property | How |
| --- | --- |
| Works with any screen reader | It is line-oriented text on stdout |
| No colour-only meaning | Every status is a **word** — `OK` / `FAIL` / `WARN` — before it is a colour |
| Honours `NO_COLOR` | Colour is dropped entirely when `NO_COLOR` is set, and whenever stdout is not a TTY |
| Degrades on limited terminals | `✓ ✗ ⚠` are used only when the stream's encoding can represent them; otherwise `OK`, `FAIL`, `WARN` |
| Machine-readable alternative | `--json` for anything that would rather parse than read |
| No animation or cursor tricks | The batch progress line goes to stderr, one line per file, no spinner or redraw |
| Errors carry a remediation | Every failure prints what to do next on its own line |

Verified by `tests/unit/test_output_rendering.py`, which asserts the ASCII
fallback, the `NO_COLOR` behaviour and the absence of colour-only signals.

## Desktop window

| Property | Status |
| --- | --- |
| Every control reachable and operable from the keyboard | **Verified** — `test_gui.py::test_every_control_is_reachable_from_the_keyboard` walks the focus ring |
| Every control has a visible text label | **Verified** by construction; no icon-only buttons exist |
| Logical focus order (file → password → output → action) | **Verified** — widgets are created and gridded in that order |
| `Return` activates the primary action, `Escape` leaves the field | **Verified** by binding; exercised manually |
| Status conveyed as text, never colour alone | **Verified** — `test_no_state_is_conveyed_by_colour_alone` |
| Password masked by default, with an explicit reveal | **Verified** — `test_password_is_masked_until_the_user_asks` |
| Window resizes and reflows; minimum 620 × 520 | **Verified** — `test_window_has_a_usable_minimum_size`; labels use `wraplength` |
| Respects the OS theme | Partial — ttk uses `aqua` on macOS, `vista` on Windows, `clam` on Linux |
| Honours OS font scaling | Partial — Tk uses `TkDefaultFont`, which follows the system size on macOS and Windows; Linux depends on the Tk build |
| Screen-reader labelling | **Not verified.** See below |
| High-contrast mode | **Not verified.** See below |

### What we could not verify, and why

Tk has no accessibility API of its own: it does not expose an accessibility
tree, and it has no equivalent of ARIA roles. On each platform it inherits
whatever the native Tk build hands to the platform's accessibility layer, which
in practice means VoiceOver, Narrator and Orca see a generic window with
generic controls rather than a richly labelled form.

Verifying that properly needs a human with the relevant screen reader on each
of the three platforms. That did not happen for this release, so this document
says so instead of claiming a conformance level nobody checked. Treating an
untested accessibility claim as true is the same class of error as treating an
untested decryption path as working — and this project refuses both.

**If a screen reader is your primary interface, use the CLI.** It is fully
accessible, it is not a fallback, and it can do everything the window can.

### Known gaps

| Gap | Impact | Workaround |
| --- | --- | --- |
| No drag-and-drop | A common expectation is missing | Use *Choose file…*; the button is the first control in the focus ring |
| No screen-reader verification | Unknown quality with VoiceOver/Narrator/Orca | Use the CLI |
| No high-contrast verification | Unknown at high contrast | Use the CLI; the OS theme is inherited but untested |
| No keyboard shortcut to reveal the password | Reachable only by tabbing to the checkbox | Tab order puts it directly after the field |

## Standards

The CLI meets the spirit of WCAG 2.1 AA as far as the concept applies to a
terminal program: text alternatives, no colour-only meaning, no timing
requirements, keyboard-only by nature.

**No WCAG conformance is claimed for the desktop window.** WCAG targets web
content, several of its success criteria have no Tk analogue, and the
criteria that do apply (1.4.3 contrast, 4.1.2 name/role/value) were not
measured. Claiming conformance without measurement would be exactly the sort
of statement this project exists not to make.

## Reporting a problem

Accessibility issues are bugs. Please open an issue saying which interface,
which assistive technology and which version — those reports are the only way
the "not verified" rows above become "verified".
