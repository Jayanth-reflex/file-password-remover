# End-to-end tests

Every other suite tests one thing at a time. These drive the product the way a
person does -- the installed executable, a real terminal, a real window, the
system file picker on a phone -- and follow a whole journey: lock a file, then
open what was written with the password that was shown.

## What runs where

| Surface | What is driven | Suite | Runs on |
| --- | --- | --- | --- |
| CLI, every feature | The installed `fpr` console script, from a directory of its own: every format, every password route, every exit code, batch, awkward names | `tests/e2e/test_features.py`, `test_journeys.py` | Linux, macOS, Windows × Python 3.10–3.13 |
| Terminals | A pseudo-terminal on macOS and Linux (colour, the password prompt, confirm-twice, Ctrl-C); a real Windows console, read back from its screen buffer | `tests/e2e/test_terminals.py` | all three |
| Shells | One journey per shell, written in that shell's idioms | `tests/e2e/shells/journey.{sh,ps1,cmd}` via `test_shells.py` | sh, dash, bash, zsh, pwsh on Linux and macOS; bash, pwsh, Windows PowerShell 5.1 and cmd.exe on Windows |
| Desktop window | The Tk window through its own controls, on its worker thread: every format, lock-then-reopen, retry, restrictions | `tests/e2e/test_desktop.py` | all three (xvfb on Linux) |
| iOS | The app on a simulator, through the system document picker, keyboard and buttons | `ios/UITests/JourneyUITests.swift` | macOS runner, via `scripts/run_ios_ui_tests.sh` |
| Android | The app on an emulator, with Compose driving the screen and Espresso-Intents answering the file picker | `android/app/src/androidTest/.../DocumentScreenJourneyTest.kt` | API 35 emulator |

A missing shell, console script or simulator is a skip on a laptop and a
failure in CI: `FPR_E2E_REQUIRE=1` refuses the skip, and `FPR_E2E_SHELLS` names
the shells each runner must have.

## Running them

```bash
make test                                   # includes tests/e2e
python -m pytest tests/e2e -q               # just the end-to-end suite
python -m pytest -m "not e2e" -q            # everything else
bash scripts/run_ios_ui_tests.sh            # iOS; picks an available iPhone
```

Android needs a running emulator and the vector corpus on it:

```bash
python scripts/gen_vectors.py build/vectors
adb push build/vectors /data/local/tmp/fpr-vectors
cd android && gradle :app:connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.fprVectors=/data/local/tmp/fpr-vectors
```

## What it has caught

Five defects, all fixed in 1.1.0, none of which any earlier suite could see
because each needs a real console, a real shell or a whole journey:

1. **A generated password could be lost.** On a console that cannot encode a
   file name -- any redirected output on Windows -- `fpr protect 税务.pdf
   --generate` wrote the encrypted file and then crashed printing its name,
   before the password line. `remove` crashed the same way after writing a
   verified output. Threat model R-17.
2. **A mistyped chosen password locked the file for good** in the desktop,
   iOS and Android apps, which took one masked field. They now ask twice, as
   the CLI always did. Threat model R-25.
3. **A PowerShell-written password file was rejected.** Windows PowerShell 5.1
   writes `"secret" > pw.txt` as UTF-16 with a byte-order mark, and Notepad
   offers UTF-8 with one; the first failed as an I/O error and the second as
   *wrong password*.
4. **An interrupted download of an encrypted PDF was called unprotected.**
   qpdf rebuilds the cross-reference table from what is left, and the result
   looks unencrypted while its streams are still ciphertext. It is now
   reported as damaged.
5. **`--suffix -open` was rejected.** The default suffix starts with a dash, so
   a dash-leading suffix is what people type; argparse read it as a flag.
