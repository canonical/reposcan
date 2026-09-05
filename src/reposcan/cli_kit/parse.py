# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The argument scanner: walk the command tree and resolve each value from argv.

One left-to-right pass. Options in scope are recognized wherever they appear;
non-option tokens select subcommands until a leaf is reached, then fill
positionals; `--` starts a verbatim remainder. Each collected value is coerced
against its parameter's `convert` and `choices` attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reposcan.cli_kit.coerce import coerce
from reposcan.cli_kit.spec import Action, Group, Param, collect_params
from reposcan.result import Err, Result, is_err


@dataclass
class Parsed:
    """A successful scan of argv against the tree.

    Exactly one of the following holds: `help`, type(`node`) == `Group`, or
    type(`command`) == Action. On the command outcome, `values` holds the coerced
    command-line values, keyed by name, for parameters actually given; absent
    parameters are left null.
    """

    prog: str
    node: type[Action | Group]
    scope: list[Param]
    values: dict[str, Any] = field(default_factory=dict)
    command: type[Action] | None = None
    help: bool = False


def parse(  # noqa: PLR0912,PLR0915  (too many branches, too many statements)
    root: type[Group], base: type[Action], argv: list[str], prog_name: str
) -> Result[Parsed]:
    """Scan `argv` against the tree; `base`'s parameters are the flow-down globals."""
    scope: dict[str, Param] = {p.name: p for p in collect_params(base)}
    node: type[Action | Group] = root
    prog = [prog_name]
    command: type[Action] | None = None
    raw: dict[str, Any] = {}
    positionals: list[str] = []
    singles: list[Param] = []
    many: Param | None = None
    remainder: Param | None = None
    no_more_options = False

    def result(**kw: Any) -> Parsed:
        return Parsed(
            prog=" ".join(prog), node=command or node, scope=list(scope.values()), **kw
        )

    def fail(message: str) -> Result[Parsed]:
        return Err(f"{' '.join(prog)}: {message}")

    i, n = 0, len(argv)
    while i < n:
        tok = argv[i]
        if not no_more_options and tok in ("-h", "--help"):
            return result(command=command, help=True)
        if not no_more_options and tok == "--":
            no_more_options = True
            i += 1
            continue
        if not no_more_options and tok.startswith("-") and tok != "-":
            key, _, inline = tok.partition("=")
            param = _find_option(scope, key)
            if param is None:
                if remainder is not None and len(positionals) >= len(singles):
                    raw[remainder.name] = argv[i:]  # an unknown option starts remainder
                    break
                return fail(f"unknown option: {key}")
            name = param.name
            # A repeatable option accumulates; any other keeps its last value.
            if not param.takes_cli_value:
                raw[name] = True
                i += 1
            elif "=" in tok:
                raw[name] = [*raw.get(name, []), inline] if param.many else inline
                i += 1
            elif i + 1 < n:
                nxt = argv[i + 1]
                raw[name] = [*raw.get(name, []), nxt] if param.many else nxt
                i += 2
            else:
                return fail(f"option {key} requires a value")
            continue

        # a positional token (or any token once options have ended)
        if command is None:
            child = _find_child(node, tok)
            if child is None:
                return fail(f"unknown command: {tok}")
            prog.append(tok)
            scope.update({p.name: p for p in collect_params(child)})
            if isinstance(child, type) and issubclass(child, Group):
                node = child
            else:
                command = child
                own = collect_params(child)
                singles = [p for p in own if p.positional and not p.many]
                many = next((p for p in own if p.positional and p.many), None)
                remainder = next((p for p in own if p.remainder), None)
            i += 1
            continue
        # at a leaf
        if len(positionals) < len(singles) or many is not None:
            positionals.append(tok)
            i += 1
            continue
        if remainder is not None:
            raw[remainder.name] = argv[i:]  # trailing tokens are the verbatim remainder
            break
        return fail(f"unexpected argument: {tok}")

    if command is None:
        return result(command=None)  # a subcommand is required
    if is_err(e := _bind_positionals(raw, positionals, singles, many)):
        return fail(e.msg)
    if remainder is not None:
        raw.setdefault(remainder.name, [])  # an absent remainder is the empty list
    coerced = _coerce_all(raw, scope)
    if isinstance(coerced, Err):
        return fail(coerced.msg)
    return result(command=command, values=coerced)


def _find_option(scope: dict[str, Param], flag: str) -> Param | None:
    for param in scope.values():
        if flag in param.flags:
            return param
    return None


def _find_child(node: type[Action | Group], name: str) -> type[Action | Group] | None:
    subcommands = getattr(node, "subcommands", ())
    for child in subcommands:
        if child.name == name:
            return child
    return None


def _bind_positionals(
    raw: dict[str, Any], tokens: list[str], singles: list[Param], many: Param | None
) -> Result[None]:
    """Distribute collected positional tokens to the single params, then the many."""
    index = 0
    for param in singles:
        if index < len(tokens):
            raw[param.name] = tokens[index]
            index += 1
        elif param.required:
            return Err(f"missing argument: {param.name}")
    if many is not None:
        raw[many.name] = tokens[index:]
    elif index < len(tokens):
        return Err(f"unexpected argument: {tokens[index]}")
    return None


def _coerce_all(raw: dict[str, Any], scope: dict[str, Param]) -> Result[dict[str, Any]]:
    """Coerce every collected command-line value against its parameter.

    Stops at the first bad value.
    """
    values: dict[str, Any] = {}
    for name, value in raw.items():
        coerced = coerce(scope[name], value)
        if isinstance(coerced, Err):
            return coerced
        values[name] = coerced
    return values
