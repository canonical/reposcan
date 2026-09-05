# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan logging utils."""

import logging
import shutil

# --verbosity choices, mapped to their logging levels ("info" is the default).
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


class _LevelFormatter(logging.Formatter):
    """Name warnings and errors with their logger; keep info messages plain."""

    _plain = logging.Formatter("reposcan: %(message)s")
    _named = logging.Formatter("reposcan: %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        chosen = self._named if record.levelno >= logging.WARNING else self._plain
        return chosen.format(record)


# Pass as `extra=` to mark a record as interactive progress. It will be redrawn over
# its predecessor on a terminal, and dropped entirely when stderr is redirected.
TRANSIENT = {"transient": True}


class _TerminalHandler(logging.StreamHandler):
    """Write records to stderr, redrawing transient logs."""

    def __init__(self) -> None:
        super().__init__()
        self._drawn = False

    def emit(self, record: logging.LogRecord) -> None:
        """Write `record`, erasing any transient line already drawn."""
        transient = getattr(record, "transient", False)
        if transient and not self.stream.isatty():
            return
        if self._drawn:
            self.stream.write("\r\033[K")  # back to column 0, clear to end of line
            self._drawn = False
        if not transient:
            super().emit(record)
            return
        # Truncated to the terminal: a wrapped line cannot be redrawn over.
        columns = shutil.get_terminal_size().columns
        self.stream.write(self.format(record)[: columns - 1])
        self.stream.flush()
        self._drawn = True


def configure_logging(verbosity: str) -> None:
    """Configure root logging at the level named by `verbosity`."""
    handler = _TerminalHandler()
    handler.setFormatter(_LevelFormatter())
    logging.basicConfig(level=LOG_LEVELS[verbosity], handlers=[handler])
