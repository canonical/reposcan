# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for cli_kit dispatch: Cli.run drives parse -> resolve -> run.

These use small synthetic command trees so they exercise the engine alone, with no
reposcan tree, resolver, env, or config. Resolving a parameter from several sources
is an application's concern, tested with reposcan's resolver (tests/unit/test_app.py).
"""

from typing import Any

from reposcan.cli_kit import Action, Cli, Group, flag, option


class _Base(Action):
    """The flow-down base: one global in scope for every command."""

    verbose: bool = flag()


class _Echo(_Base):
    name = "echo"
    help = "return a chosen exit code"
    code: int = option(convert=int, default=0)

    def run(self) -> int:
        return self.code


def _tree(*commands: type) -> type[Group]:
    attrs = {"name": "app", "help": "root", "subcommands": commands}
    return type("Root", (Group,), attrs)


def _cli(*commands: type) -> Cli:
    return Cli("app", root=_tree(*commands), base=_Base)  # no resolver


def test_run_dispatches_to_a_command_and_returns_its_exit_code() -> None:
    assert _cli(_Echo).run(["echo", "--code", "5"]) == 5
    assert _cli(_Echo).run(["echo"]) == 0  # code takes its default


def test_a_global_flows_down_and_is_accepted_before_or_after_the_command() -> None:
    captured: dict[str, Any] = {}

    class _Show(_Base):
        name = "show"
        help = ""

        def run(self) -> int:
            captured["verbose"] = self.verbose
            return 0

    assert _cli(_Show).run(["--verbose", "show"]) == 0
    assert captured["verbose"] is True  # before the subcommand
    assert _cli(_Show).run(["show", "--verbose"]) == 0
    assert captured["verbose"] is True  # and after it


def test_usage_errors_return_2() -> None:
    cli = _cli(_Echo)
    assert cli.run(["frobnicate"]) == 2  # unknown command
    assert cli.run(["--nope", "echo"]) == 2  # unknown option
    assert cli.run(["echo", "--code", "notanumber"]) == 2  # value fails to convert


def test_a_group_without_a_chosen_subcommand_is_a_usage_error() -> None:
    inner = type(
        "Inner", (Group,), {"name": "grp", "help": "g", "subcommands": (_Echo,)}
    )
    cli = Cli("app", root=_tree(inner), base=_Base)
    assert cli.run(["grp"]) == 2  # a subcommand is required


def test_a_help_request_prints_and_returns_0() -> None:
    assert _cli(_Echo).run(["--help"]) == 0
    assert _cli(_Echo).run(["echo", "--help"]) == 0


def test_an_unmet_requirement_is_rejected_before_the_command_runs() -> None:
    ran: list[bool] = []

    class _Need(_Base):
        name = "need"
        help = ""
        mode: str = option(choices=("a", "b"), default="a")
        depth: int | None = option(convert=int, requires={"mode": "b"})

        def run(self) -> int:
            ran.append(True)
            return 0

    # --depth requires --mode=b; with the default mode 'a' it is a usage error.
    assert _cli(_Need).run(["need", "--depth", "3"]) == 2
    assert not ran  # rejected before the command runs


def test_with_no_resolver_values_come_from_the_command_line_and_defaults() -> None:
    captured: dict[str, Any] = {}

    class _Cmd(_Base):
        name = "cmd"
        help = ""
        mode: str = option(default="plain")

        def run(self) -> int:
            captured.update(mode=self.mode, verbose=self.verbose)
            return 0

    _cli(_Cmd).run(["cmd", "--mode", "rich"])
    assert captured == {"mode": "rich", "verbose": False}  # cli value plus defaults
