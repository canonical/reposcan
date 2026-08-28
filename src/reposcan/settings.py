# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Parameter-value resolution.

`resolve` is injected to the cli_kit `Cli`: for each in-scope parameter it
takes the value from the command line, then a REPOSCAN_* env var, then the
saved config file, falling back to the parameter's default.
"""

import logging
import os
from collections.abc import Mapping
from typing import Any

from reposcan.actions.base import Action
from reposcan.cli_kit import Param, coerce, params_of
from reposcan.config import load
from reposcan.logging import configure_logging

logger = logging.getLogger(__name__)

# The environment-variable stem every env-settable parameter is read from.
ENV_PREFIX = "REPOSCAN_"

# Sentinel meaning "no source supplied this parameter"; cli_kit then fills its default.
_UNSET: Any = object()

# parameters persisted in config
_CONFIG_KEYS = frozenset(p.name for p in params_of(Action))


def resolve(scope: list[Param], cli_values: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve reposcan's parameters: CLI > REPOSCAN_* env > config > default.

    injected to Cli.run; `cli_values` are the parsed command-line values. this overrides
    or injects additional parameters from other sources.
    """
    config = load()
    configure_logging(_verbosity(scope, cli_values, config))
    values: dict[str, Any] = {}
    for param in scope:
        value = _resolve_one(param, cli_values, os.environ, config)
        if value is not _UNSET:
            values[param.name] = value
    return values


def _verbosity(
    scope: list[Param], cli_values: Mapping[str, Any], config: Mapping[str, Any]
) -> str:
    """The resolved verbosity level, falling back to its default when unset."""
    param = next((p for p in scope if p.name == "verbosity"), None)
    if param is None:
        return "info"
    value = _resolve_one(param, cli_values, os.environ, config)
    return str(value) if value is not _UNSET else str(param.default or "info")


def _resolve_one(
    param: Param,
    cli_values: Mapping[str, Any],
    env: Mapping[str, str],
    config: Mapping[str, Any],
) -> Any:
    """The value resolved for `param`, or `_UNSET` if no source sets it.

    Precedence is the command line, then a REPOSCAN_* env var, then the saved config.
    """
    present: list[tuple[str, Any]] = []
    if param.name in cli_values:
        present.append(("cli", cli_values[param.name]))
    ambient: list[tuple[str, Any]] = []
    if not (param.positional or param.remainder):
        ambient.append(("env", env.get(_env_var(param.name))))
    if param.name in _CONFIG_KEYS:
        ambient.append(("config", config.get(param.name)))
    for source, raw in ambient:
        if raw is None:
            continue
        value, error = coerce(param, raw)
        if error is not None:
            logger.warning("ignoring invalid %s %s: %s", source, param.name, error)
            continue
        present.append((source, value))
    if not present:
        return _UNSET
    winner_source, winner = present[0]
    for source, value in present[1:]:
        if value != winner:
            logger.info("%s overrode %s for %s", winner_source, source, param.name)
    return winner


def _env_var(name: str) -> str:
    """The environment variable that sets the parameter named `name`."""
    return ENV_PREFIX + name.upper().replace("-", "_").replace(" ", "_")
