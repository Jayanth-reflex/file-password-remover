"""Frozen entry point for the CLI.

PyInstaller runs its entry script as ``__main__``, so pointing it straight at
``src/fpr/cli/main.py`` breaks every relative import in the package. This shim
imports the package properly and calls into it, which is also what the
``fpr`` console script does when installed from a wheel.
"""

import sys

from fpr.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
