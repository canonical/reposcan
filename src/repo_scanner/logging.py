# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan logging utils."""

import logging

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


def configure_logging(verbosity: str) -> None:
    """Configure root logging at the level named by `verbosity`."""
    handler = logging.StreamHandler()
    handler.setFormatter(_LevelFormatter())
    logging.basicConfig(level=LOG_LEVELS[verbosity], handlers=[handler])
