# Uninstalling

The short version: there is nothing to clean up. The tool writes no
configuration, no cache, no logs and no registry entries, so removing the
package removes the software completely.

## pip

```bash
pip uninstall file-password-remover
```

That also removes the `fpr` and `fpr-gui` commands. The libraries it pulled in
(`pikepdf`, `msoffcrypto-tool`, `pyzipper`, and `py7zr` if you installed the
extra) stay, because pip does not remove dependencies. To take them too:

```bash
pip uninstall file-password-remover pikepdf msoffcrypto-tool pyzipper py7zr \
              cryptography olefile lxml pillow pycryptodomex
```

Check whether anything else needs them first:

```bash
pip install pipdeptree && pipdeptree --reverse --packages pikepdf
```

## pipx

```bash
pipx uninstall file-password-remover
```

Removes the isolated environment and the shims in one step.

## Standalone bundle

Delete the directory you unpacked, and any symlink you made:

```bash
rm -rf ~/Applications/file-password-remover
rm -f ~/.local/bin/fpr ~/.local/bin/fpr-gui
```

On Windows, delete the folder from `%LOCALAPPDATA%\Programs` and remove the
entry you added to `PATH`, if you added one.

## Virtualenv from source

```bash
rm -rf /path/to/file-password-remover      # the clone, including .venv
```

## What is left behind

Nothing that belongs to this tool:

| | |
| --- | --- |
| Config files | none are written |
| Cache | none is written |
| Logs | none are written; diagnostics go to stderr and are not persisted |
| Registry / plist / dconf entries | none |
| Recent-files list | none |
| Temporary files | created inside the output's directory and deleted at the end of every run, including failed ones |
| Network state | there is none; the package contains no network code |

**Your output files stay.** Every unprotected copy the tool wrote is an
ordinary file that belongs to you. If you want them gone, delete them
yourself — the tool will not go looking for its past output, because that
would mean keeping a record of what you processed, which it deliberately does
not do.

If you created password files (`--password-file`), delete those too:

```bash
rm -P ~/pw.txt          # macOS: overwrite before unlinking
shred -u ~/pw.txt       # Linux
```

Note the same caveat that applies to the tool's own scrubbing: on SSDs and
copy-on-write filesystems, overwriting does not reliably erase the underlying
blocks.
