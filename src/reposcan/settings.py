# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Parameter-value resolution: the resolver reposcan injects into the cli_kit Cli."""

import logging
import os
from collections.abc import Mapping
from typing import Any

from reposcan.actions.base import Action
from reposcan.cli_kit import Param, coerce, collect_params
from reposcan.config import load
from reposcan.logging import configure_logging
from reposcan.result import Err

logger = logging.getLogger(__name__)

# The environment-variable stem every env-settable parameter is read from.
ENV_PREFIX = "REPOSCAN_"

# Sentinel meaning "no source supplied this parameter"; cli_kit then fills its default.
_UNSET: Any = object()

# parameters persisted in config
_CONFIG_KEYS = frozenset(p.name for p in collect_params(Action))

# Parameters that cannot be set by an environment variable.
_NO_ENV_KEYS = frozenset({"env"})


def resolve(scope: list[Param], cli_values: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve reposcan's parameters: CLI > REPOSCAN_* env > config > default.

    Called by `Cli.run` with every in-scope parameter and `cli_values`, the values the
    command line supplied. A parameter no source sets is left out, so cli_kit fills its
    default.
    """
    config = load()
    configure_logging(_select_verbosity(scope, cli_values, config))
    values: dict[str, Any] = {}
    for param in scope:
        value = _resolve_one(param, cli_values, os.environ, config)
        if value is not _UNSET:
            values[param.name] = value
    return values


def _select_verbosity(
    scope: list[Param], cli_values: Mapping[str, Any], config: Mapping[str, Any]
) -> str:
    """Select the logging verbosity level."""
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
    """Resolve `param` from its sources.

    Positionals, remainders, and `_NO_ENV_KEYS` are never read from the environment.
    An env or config value that will not coerce is warned about and skipped rather
    than failing the command. Two sources with disagreeing values produce a log.

    Returns:
        The winning value, or `_UNSET` if no source sets it.
    """
    present: list[tuple[str, Any]] = []
    if param.name in cli_values:
        present.append(("cli", cli_values[param.name]))
    ambient: list[tuple[str, Any]] = []
    if not (param.positional or param.remainder or param.name in _NO_ENV_KEYS):
        ambient.append(("env", env.get(param.env_var or _derive_env_name(param.name))))
    if param.name in _CONFIG_KEYS:
        ambient.append(("config", config.get(param.name)))
    for source, raw in ambient:
        if raw is None:
            continue
        result = coerce(param, raw)
        if isinstance(result, Err):
            logger.warning("ignoring invalid %s %s: %s", source, param.name, result.msg)
            continue
        present.append((source, result))
    if not present:
        return _UNSET
    winner_source, winner = present[0]
    for source, value in present[1:]:
        if value != winner:
            logger.info("%s overrode %s for %s", winner_source, source, param.name)
    return winner


def _derive_env_name(name: str) -> str:
    """Derive the environment variable name a parameter reads from."""
    return ENV_PREFIX + name.upper().replace("-", "_").replace(" ", "_")
