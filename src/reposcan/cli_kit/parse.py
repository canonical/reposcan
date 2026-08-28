# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The argument scanner: walk the command tree and resolve each value from argv.

One left-to-right pass. Options in scope are recognized wherever they appear;
non-option tokens select subcommands until a leaf is reached, then fill
positionals; `--` starts a verbatim remainder. Each collected value is coerced
against its parameter `convert` and `choices` attributes, so `Parsed.values`
holds finished, typed command-line values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reposcan.cli_kit.coerce import coerce
from reposcan.cli_kit.spec import Action, Group, Param, params_of


@dataclass
class Parsed:
    """The outcome of scanning argv against the tree.

    Exactly one of the following conditions will be truthy: `error`, `help`,
    type(`node`) == `Group`, or type(`command`) == Action. On the command outcome,
    `values` holds the coerced command-line values, keyed by name, for parameters
    actually given; absent parameters are left null.
    """

    prog: str
    node: type[Action | Group]
    scope: list[Param]
    values: dict[str, Any] = field(default_factory=dict)
    command: type[Action] | None = None
    help: bool = False
    error: str | None = None


def parse(
    root: type[Group], base: type[Action], argv: list[str], prog_name: str
) -> Parsed:
    """Scan `argv` against the tree; `base`'s parameters are the flow-down globals."""
    scope: dict[str, Param] = {p.name: p for p in params_of(base)}
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
                return result(command=command, error=f"unknown option: {key}")
            if not param.takes_cli_value:
                raw[param.name] = True
                i += 1
            elif "=" in tok:
                raw[param.name] = inline
                i += 1
            elif i + 1 < n:
                raw[param.name] = argv[i + 1]
                i += 2
            else:
                return result(command=command, error=f"option {key} requires a value")
            continue

        # a positional token (or any token once options have ended)
        if command is None:
            child = _child(node, tok)
            if child is None:
                return result(error=f"unknown command: {tok}")
            prog.append(tok)
            scope.update({p.name: p for p in params_of(child)})
            if isinstance(child, type) and issubclass(child, Group):
                node = child
            else:
                command = child
                own = params_of(child)
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
        return result(command=command, error=f"unexpected argument: {tok}")

    if command is None:
        return result(command=None)  # a subcommand is required
    error = _bind_positionals(raw, positionals, singles, many)
    if error is not None:
        return result(command=command, error=error)
    if remainder is not None:
        raw.setdefault(remainder.name, [])  # an absent remainder is the empty list
    values, error = _coerce_all(raw, scope)
    if error is not None:
        return result(command=command, error=error)
    return result(command=command, values=values)


def _find_option(scope: dict[str, Param], flag: str) -> Param | None:
    for param in scope.values():
        if flag in param.flags:
            return param
    return None


def _child(node: type[Action | Group], name: str) -> type[Action | Group] | None:
    subcommands = getattr(node, "subcommands", ())
    for child in subcommands:
        if child.name == name:
            return child
    return None


def _bind_positionals(
    raw: dict[str, Any], tokens: list[str], singles: list[Param], many: Param | None
) -> str | None:
    """Distribute collected positional tokens to the single params, then the many."""
    index = 0
    for param in singles:
        if index < len(tokens):
            raw[param.name] = tokens[index]
            index += 1
        elif param.required:
            return f"missing argument: {param.name}"
    if many is not None:
        raw[many.name] = tokens[index:]
    elif index < len(tokens):
        return f"unexpected argument: {tokens[index]}"
    return None


def _coerce_all(
    raw: dict[str, Any], scope: dict[str, Param]
) -> tuple[dict[str, Any], str | None]:
    """Coerce every collected command-line value against its parameter.

    Returns the coerced values, or ({}, message) on the first bad value.
    """
    values: dict[str, Any] = {}
    for name, value in raw.items():
        coerced, error = _coerce_value(scope[name], value)
        if error is not None:
            return {}, error
        values[name] = coerced
    return values, None


def _coerce_value(param: Param, raw: Any) -> tuple[Any, str | None]:
    """Coerce one value: a remainder verbatim, a `many` per item, else a scalar."""
    if param.remainder:
        return list(raw), None
    if param.many:
        out = []
        for item in raw:
            value, error = coerce(param, item)
            if error is not None:
                return None, error
            out.append(value)
        return out, None
    return coerce(param, raw)
