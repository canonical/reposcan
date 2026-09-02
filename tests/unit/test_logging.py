# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for reposcan.logging."""

import io
import logging

from reposcan.logging import TRANSIENT, _LevelFormatter, _TerminalHandler


class _Stream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _emitted(*records: tuple[str, bool], tty: bool) -> str:
    """The bytes a handler on a `tty` (or not) writes for (message, transient) pairs."""
    handler = _TerminalHandler()
    handler.setFormatter(_LevelFormatter())
    handler.stream = _Stream(tty=tty)
    for message, transient in records:
        record = logging.LogRecord("t", logging.INFO, "f", 1, message, None, None)
        if transient:
            record.__dict__.update(TRANSIENT)  # what `extra=` does at the call site
        handler.emit(record)
    return handler.stream.getvalue()


def test_a_transient_record_is_redrawn_in_place_then_erased_by_the_next_line() -> None:
    written = _emitted(("one", True), ("two", True), ("done", False), tty=True)
    # nothing to erase before the first; each later write returns to column 0 and
    # clears, so all three occupy one line
    assert written == ("reposcan: one\r\033[Kreposcan: two\r\033[Kreposcan: done\n")


def test_a_transient_record_is_dropped_when_stderr_is_not_a_terminal() -> None:
    # A redirect or a CI log wants the result, not a running count -- and cannot
    # redraw anyway, so the escape codes must not reach it either.
    written = _emitted(("one", True), ("done", False), tty=False)
    assert written == "reposcan: done\n"
