# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""`reposcan config` commands."""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.cli_kit import Group, coerce, params_of, positional
from reposcan.config import load, save
from reposcan.table import render_table

logger = logging.getLogger(__name__)

_KEYS = {p.name: p for p in params_of(Action)}


class ConfigSet(Action):
    name = "set"
    help = "Set a config value."

    key: str = positional(help="The config key to set.")
    value: str = positional(help="The value to store.")

    def run(self) -> int:
        param = _KEYS.get(self.key)
        if param is None:
            logger.error("unknown config key: %s", self.key)
            return 2
        _, error = coerce(param, self.value)
        if error is not None:
            logger.error("%s", error)
            return 2
        settings = load()
        settings[self.key] = self.value
        error = save(settings)
        if error is not None:
            logger.error("%s", error)
            return 1
        return 0


class ConfigGet(Action):
    name = "get"
    help = "Get a config value, or all values when no key is given."

    key: str | None = positional(required=False, help="The config key to read.")

    def run(self) -> int:
        settings = load()
        if self.key is None:
            rows = [[name, str(value)] for name, value in sorted(settings.items())]
            sys.stdout.write(render_table(["key", "value"], rows))
            return 0
        if self.key not in _KEYS:
            logger.error("config key '%s' is not known", self.key)
        if self.key not in settings:
            logger.error("config key not set: %s", self.key)
            return 1
        sys.stdout.write(f"{settings[self.key]}\n")
        return 0


class ConfigUnset(Action):
    name = "unset"
    help = "Remove a config value."

    key: str = positional(help="The config key to remove.")

    def run(self) -> int:
        settings = load()
        if self.key not in settings:
            logger.info("config key not set: %s", self.key)
            return 0
        del settings[self.key]
        error = save(settings)
        if error is not None:
            logger.error("%s", error)
            return 1
        return 0


class ConfigKeys(Action):
    name = "keys"
    help = "List all supported config keys."

    def run(self) -> int:
        rows = [[name, param.help] for name, param in sorted(_KEYS.items())]
        sys.stdout.write(render_table(["key", "description"], rows))
        return 0


class ConfigOptions(Action):
    name = "options"
    help = "List the supported values for a config key."

    key: str = positional(help="The config key to describe.")

    def run(self) -> int:
        param = _KEYS.get(self.key)
        if param is None:
            logger.error("unknown config key: %s", self.key)
            return 2
        if param.choices is not None:
            for choice in param.choices:
                sys.stdout.write(f"{choice}\n")
            return 0
        sys.stdout.write(f"{self.key} accepts any value: {param.help}\n")
        return 0


class ConfigGroup(Group):
    name = "config"
    help = "Get or set persistent configuration."
    subcommands = (ConfigSet, ConfigGet, ConfigUnset, ConfigKeys, ConfigOptions)
