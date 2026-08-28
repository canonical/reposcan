# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for parameter resolution."""

import logging
import os
import sys
from typing import Any

from repo_scanner import settings
from repo_scanner.actions.base import Action
from repo_scanner.app import Reposcan, main
from repo_scanner.cli_kit import Group, option, parse
from repo_scanner.logging import LOG_LEVELS


def _resolve_isolated(scope, cli_values, env):
    """Run reposcan's resolver with os.environ set to `env` and the config store empty.

    reposcan's resolver reads os.environ and the config store directly, so isolate
    both here (save and restore).
    """
    saved_environ = dict(os.environ)
    saved_load = settings.load
    os.environ.clear()
    os.environ.update(env or {})
    settings.load = lambda: {}
    try:
        resolved = settings.resolve(scope, cli_values)
    finally:
        os.environ.clear()
        os.environ.update(saved_environ)
        settings.load = saved_load
    return {p.name: resolved.get(p.name, p.default) for p in scope}


def _resolved(argv: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    """Parse `argv` against the real tree and resolve, with no env/config by default."""
    parsed = parse(Reposcan, Action, argv, "reposcan")
    assert parsed.error is None, parsed.error
    return _resolve_isolated(parsed.scope, parsed.values, env)


# --- the wired CLI, end to end through main ----------------------------------


def test_main_forwards_the_command_exit_code() -> None:
    prog = [sys.executable, "-c", "raise SystemExit(5)"]
    assert main(["--backend", "local", "exec", "--", *prog]) == 5


def test_verbosity_configures_root_logging_before_dispatch() -> None:
    saved = logging.getLogger().level
    try:
        prog = [sys.executable, "-c", ""]
        main(["--verbosity", "warning", "--backend", "local", "exec", "--", *prog])
        assert logging.getLogger().level == LOG_LEVELS["warning"]
    finally:
        logging.getLogger().setLevel(saved)


# --- resolution precedence: CLI > env > config > default ----------------------


def test_a_global_resolves_from_the_middle_of_a_deep_command() -> None:
    values = _resolved(["image", "cache", "--backend", "local", "remove", "r1"])
    assert values["backend"] == "local"
    assert values["reference"] == "r1"


def test_cli_beats_env_beats_default_for_a_global() -> None:
    assert _resolved(["exec", "--", "x"])["backend"] == "auto"  # default
    with_env = _resolved(["exec", "--", "x"], {"REPOSCAN_BACKEND": "lxd"})
    assert with_env["backend"] == "lxd"  # env over default
    with_cli = _resolved(
        ["--backend", "local", "exec", "--", "x"], {"REPOSCAN_BACKEND": "docker"}
    )
    assert with_cli["backend"] == "local"  # cli over env


def test_an_invalid_env_value_is_ignored_not_fatal() -> None:
    # A bad ambient value warns and falls through (like a malformed config file),
    # rather than aborting; a bad command-line value, by contrast, is a usage error.
    assert _resolved(["exec", "--", "x"], {"REPOSCAN_UID": "-1"})["uid"] is None


# --- scan options resolve like any other --------------------------------------


class _FauxScan(Action):
    """A test-only command for exercising option resolution."""

    name = "faux"
    help = "A fake command for testing resolution."

    flavor: str = option(choices=("plain", "rich"), default="plain", help="the flavor")
    level: int | None = option(
        convert=int, requires={"flavor": "rich"}, help="detail level"
    )

    def run(self) -> int:
        return 0


def _fake_scan_tree() -> type[Group]:
    return type(
        "Root", (Group,), {"name": "reposcan", "help": "", "subcommands": (_FauxScan,)}
    )


def _resolved_scan(argv: list[str]) -> dict[str, Any]:
    parsed = parse(_fake_scan_tree(), Action, argv, "reposcan")
    assert parsed.error is None, parsed.error
    return _resolve_isolated(parsed.scope, parsed.values, None)


def test_scan_options_resolve_like_any_other() -> None:
    assert _resolved_scan(["faux"])["flavor"] == "plain"  # default
    assert _resolved_scan(["faux", "--flavor", "rich"])["flavor"] == "rich"
    assert _resolved_scan(["faux", "--level", "3"])["level"] == 3  # converted


def test_a_boolean_scan_flag_resolves_from_cli_env_and_default() -> None:
    # --include-dev-dependencies is a real, env-settable flag on the sca scan and the
    # sbom command.
    for argv in (["scan", "sca", "."], ["sbom", "."]):
        assert _resolved(argv)["include_dev_dependencies"] is False
        with_cli = _resolved([*argv, "--include-dev-dependencies"])
        assert with_cli["include_dev_dependencies"] is True
        with_env = _resolved(argv, {"REPOSCAN_INCLUDE_DEV_DEPENDENCIES": "1"})
        assert with_env["include_dev_dependencies"] is True
