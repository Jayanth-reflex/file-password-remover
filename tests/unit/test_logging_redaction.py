"""Nothing that looks like a credential reaches a log handler."""

from __future__ import annotations

import io
import logging

import pytest

from fpr.logging_setup import REDACTED, RedactionFilter, configure


@pytest.mark.parametrize(
    "message",
    [
        "password: hunter2",
        "passphrase = hunter2",
        "opening with --password hunter2",
        "the password is hunter2",
        "SECRET: hunter2",
    ],
)
def test_credential_shapes_are_scrubbed(message: str) -> None:
    stream = io.StringIO()
    configure(2, stream=stream)
    logging.getLogger("fpr.test").error(message)
    written = stream.getvalue()
    assert "hunter2" not in written
    assert REDACTED in written


def test_ordinary_messages_survive() -> None:
    stream = io.StringIO()
    configure(2, stream=stream)
    logging.getLogger("fpr.test").info("removing protection from report.pdf")
    assert "report.pdf" in stream.getvalue()


def test_filter_never_raises_on_a_broken_record() -> None:
    record = logging.LogRecord("x", logging.INFO, "f", 1, "%d", ("not-an-int",), None)
    assert RedactionFilter().filter(record) is True
