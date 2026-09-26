"""Helpers shared by every test that drives the desktop window."""

from __future__ import annotations

import time
from typing import Any


def settle(app: Any, timeout: float = 20.0) -> None:
    """Pump the Tk event loop until the worker thread's result is applied."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.root.update()
        if not app.busy:
            return
        time.sleep(0.02)
    raise AssertionError("the worker never finished")
