# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the parameter spec, in particular flag inference (reposcan.cli_kit).

An option/flag's long spelling `--<name>` is inferred from its attribute name; the
flags passed to the constructor are only extra spellings. Positionals and remainders
get no flags.
"""

import pytest

from reposcan.actions.base import Action as Globals
from reposcan.cli_kit import (
    Action,
    check_requires,
    flag,
    option,
    params_of,
    positional,
    remainder,
)


class _Sample:
    plain: str = option()
    short: str = option("-s")
    multi_word: bool = flag()
    explicit_long: str = option("--explicit-long")  # already given: not duplicated
    pos: str = positional()
    rest: list[str] = remainder()


def _flags(cls: type) -> dict[str, tuple[str, ...]]:
    return {p.name: p.flags for p in params_of(cls)}


def test_the_long_flag_is_inferred_and_extra_flags_are_kept() -> None:
    flags = _flags(_Sample)
    assert flags["plain"] == ("--plain",)  # inferred from the name
    assert flags["short"] == ("-s", "--short")  # extra short kept, long inferred
    assert flags["multi_word"] == ("--multi-word",)  # a flag, name kebab-cased
    assert flags["explicit_long"] == ("--explicit-long",)  # not duplicated
    assert flags["pos"] == ()  # positionals get no flags
    assert flags["rest"] == ()  # nor remainders


def test_the_real_globals_infer_their_flags() -> None:
    flags = _flags(Globals)
    assert flags["backend"] == ("--backend",)
    assert flags["verbosity"] == ("-v", "--verbosity")
    assert flags["uid"] == ("--uid",)
    assert flags["image"] == ("--image",)


class _Fields(Action):
    name = "x"
    help = "a command with a few parameters"
    mode: str = option(choices=("a", "b"), default="a")
    depth: int | None = option(convert=int, requires={"mode": "b"})
    argv: list[str] = remainder()


def test_a_command_is_a_constructable_value_object_with_defaults() -> None:
    default = _Fields()
    assert default.mode == "a" and default.depth is None and default.argv == []
    given = _Fields(mode="b", depth=5)
    assert given.mode == "b" and given.depth == 5
    assert _Fields().argv is not _Fields().argv  # each gets its own remainder list


def test_a_command_rejects_unknown_arguments() -> None:
    with pytest.raises(TypeError):
        _Fields(bogus=1)


def test_check_requires_enforces_a_dependency_only_when_the_option_is_set() -> None:
    params = params_of(_Fields)
    assert check_requires(params, {"mode": "a", "depth": None}) is None  # depth unset
    assert check_requires(params, {"mode": "b", "depth": 5}) is None  # satisfied
    assert (
        check_requires(params, {"mode": "a", "depth": 5}) == "--depth requires --mode=b"
    )


class _WithExtra(Action):
    name = "y"
    help = "a command that folds in a data-declared option via extra_options"
    depth: int | None = option(convert=int)
    extra_options = (option(name="flavor", choices=("plain", "rich"), default="plain"),)


def test_extra_options_are_folded_in_beside_own_parameters() -> None:
    aggregated = {p.name: p for p in params_of(_WithExtra)}
    assert {"depth", "flavor"} <= set(aggregated)  # own attribute plus the extra
    assert aggregated["flavor"].flags == ("--flavor",)  # data name infers the long flag
    assert vars(_WithExtra(flavor="rich"))["flavor"] == "rich"  # populates self.<name>


class _AnyOf(Action):
    name = "z"
    help = "a command whose option requires any of several, or membership in a list"
    picks: list[str] = positional(many=True)
    detail: int | None = option(convert=int, requires={"picks": ("a", "b")})


def test_check_requires_supports_any_of_and_list_membership() -> None:
    params = params_of(_AnyOf)
    # `detail` requires that `picks` (a list) contain "a" or "b".
    assert check_requires(params, {"picks": ["a", "c"], "detail": 1}) is None
    error = check_requires(params, {"picks": ["c"], "detail": 1})
    assert error == "--detail requires a or b among picks"
