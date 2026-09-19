# Localization

## Status, in one line

The interface is localisation-ready; English is the only catalogue that ships;
engine and adapter messages are not yet externalised.

That is a partial answer, and it is stated as one.

## How it works

`fpr/i18n.py` resolves a key against a JSON catalogue in `fpr/locales/`,
falling back to the English source text that is passed in at the call site:

```python
from fpr.i18n import t

t("gui.remove", "Remove protection")
t("gui.status.ok", "Done. Verified copy written to {path}.", path=str(output))
```

The English default is **mandatory**. A missing catalogue entry therefore shows
readable English rather than a dotted key like `gui.status.ok` — the failure
mode that makes half-translated software unusable.

JSON was chosen over gettext deliberately: contributing a translation needs a
text editor and nothing else — no `msgfmt`, no `.po`/`.mo` build step, no
toolchain to install on Windows. The cost is losing gettext's plural forms and
translator comments. For an interface of roughly thirty strings that is the
right trade; if the string count grows past a few hundred, migrating to gettext
would be the moment to reconsider.

## Language selection

In order:

1. `FPR_LANG`
2. `LC_ALL`
3. `LC_MESSAGES`
4. `LANG`
5. the process locale via `locale.getlocale()`
6. `en`

`C` and `POSIX` are treated as *no* locale rather than as a language. Only the
language part is used: `fr_CA.UTF-8` → `fr`. Region-specific catalogues are not
supported today; if `pt_BR` and `pt_PT` need to diverge, the resolver gains one
lookup.

```bash
FPR_LANG=fr fpr-gui        # uses locales/fr.json if present, else English
```

## Adding a language

1. Copy `src/fpr/locales/en.json` to `src/fpr/locales/<code>.json`.
2. Translate the values. Leave the keys alone.
3. Keep every `{placeholder}` intact and in a natural position for the
   language — they are `str.format` names, not positional.
4. Run `pytest tests/unit/test_i18n.py`.
5. Open a pull request. No build step, no compiled artifact.

A malformed catalogue cannot break the UI: a bad placeholder falls back to the
English source, and unparseable JSON falls back to an empty catalogue.
`tests/unit/test_i18n.py::test_a_broken_translation_falls_back_instead_of_raising`
covers this.

## What is *not* localised yet, and what it would take

| Surface | Status |
| --- | --- |
| Desktop window | Externalised through `t()` |
| CLI help and usage | English (argparse's own strings) |
| Engine and adapter messages — the detailed explanations of protection types | **English only.** These are the most valuable strings to translate and the most work: roughly 60 messages defined at their source in `adapters/` and `errors.py`, each carrying a remediation line |
| Exception messages in the Python API | English only, by design — they are developer-facing |
| Documentation | English only |

Externalising the adapter messages means routing `FprError.message` and
`Detection.detail` through `t()` with stable keys. It was left out of 1.0.0
rather than done badly: half-translated error messages, where the headline is
in the user's language and the explanation is not, are worse than consistent
English.

## Conventions for translators

- **Never translate**: format names (PDF, ECMA-376), algorithm names (AES-256,
  ZipCrypto), CLI flags (`--remove-restrictions`), file extensions.
- **Do translate**: everything a user reads as prose, including the warnings.
- **Tone**: plain and specific. The English text avoids exclamation marks and
  avoids blaming the user; please keep that.
- **Length**: the desktop window wraps at 560 px. A translation 40 % longer
  than the English still fits; one three times as long will not.

## Right-to-left

Untested. Tk's RTL support is limited and no RTL catalogue exists yet, so
nothing is claimed. The first Arabic or Hebrew catalogue will need layout work
in `fpr_gui/app.py`, not just a JSON file.
