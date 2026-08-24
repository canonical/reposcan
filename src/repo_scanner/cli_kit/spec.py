# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Command declaration surface: parameters, commands, groups, and the application.

This is the neutral vocabulary a command declares itself with, independent of the
CLI engine (which imports it, not the other way round).

A command is a class: it declares its parameters as typed class attributes and
implements `run`. On dispatch the engine resolves every in-scope parameter (via the
application's resolver) and populates the instance, so `run` reads them as plain
typed attributes:

    class CacheRemove(Action):
        name = "remove"
        help = "Remove one entry by its image reference."
        reference: str = positional(help="Image reference to forget.")

        def run(self) -> int:
            ...                                         # self.reference: str

Flow-down: parameters declared on the command base (the globals) are in scope for
every command and may appear anywhere in the arguments, before or after any
subcommand, at any depth -- so `self.backend` is available in every `run`, and
`reposcan image cache --backend docker remove r1` is accepted. A global is simply a
parameter declared on the base.

Parsing and help rendering live in `repo_scanner.cli_kit`; resolution (turning
parsed tokens plus any external sources into values) is supplied by the application
as the `Cli` resolver. This module is the declaration surface plus the `Cli.run`
entry point.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, ClassVar, Generic, TypeVar

T = TypeVar("T")

# A client-provided function. Given a command's parameters and the coerced
# command-line values (the parameters actually given), it returns a potentically
# changed set of parameter values.
Resolver = Callable[[list["Param"], Mapping[str, Any]], dict[str, Any]]


class Param(Generic[T]):
    """A parameter.

    Used as the default of a typed class attribute on a command; the attribute name
    becomes the parameter's identity -- the resolved-value key, the name a resolver
    reads it by from each source, and the label in override logs. Build one with
    `option`/`flag`/`positional`/`remainder` rather than directly.
    """

    def __init__(
        self,
        *,
        name: str = "",
        flags: tuple[str, ...] = (),
        help: str = "",
        default: Any = None,
        choices: tuple[Any, ...] | None = None,
        convert: Callable[[str], Any] | None = None,
        positional: bool = False,
        remainder: bool = False,
        many: bool = False,
        required: bool = True,
        is_flag: bool = False,
        requires: dict[str, str | tuple[str, ...]] | None = None,
    ) -> None:
        self.name = name  # else set by __set_name__ from the class-attribute name
        self.flags = flags
        self.help = help
        self.default = default
        self.choices = choices
        self.convert = convert
        self.positional = positional
        self.remainder = remainder
        self.many = many
        self.required = required
        self.is_flag = is_flag
        # A cross-parameter dependency: another parameter -> the value(s) it must have
        # (or, for a list-valued parameter, contain) for this one to be valid; a tuple
        # means any-of. Enforced by `check_requires` only when this parameter is set.
        self.requires = requires
        if name:
            self._ensure_long_flag()

    def __set_name__(self, owner: type, name: str) -> None:
        """Capture attribute name.

        Magic method called once during class definition; captures the class attribute
        name that this Param instance is assigned to.
        """
        if not self.name:
            self.name = name
        self._ensure_long_flag()

    def _ensure_long_flag(self) -> None:
        """Add the `--<name>` spelling for an option/flag, if not already present."""
        if self.positional or self.remainder:
            return
        long = "--" + self.name.replace("_", "-")
        if long not in self.flags:
            self.flags = (*self.flags, long)

    @property
    def takes_cli_value(self) -> bool:
        """Whether the option consumes a following argument on the command line."""
        return not (self.is_flag or self.positional or self.remainder)

    def __repr__(self) -> str:
        return f"Param({self.name!r})"


def _as_flags(extra_flags: str | Iterable[str] | None) -> tuple[str, ...]:
    """Normalize `extra_flags` (a single flag, an iterable, or None) to a tuple."""
    if extra_flags is None:
        return ()
    if isinstance(extra_flags, str):
        return (extra_flags,)
    return tuple(extra_flags)


def option(
    extra_flags: str | Iterable[str] | None = None,
    *,
    name: str = "",
    default: T | None = None,
    choices: tuple[T, ...] | None = None,
    convert: Callable[[str], T] | None = None,
    help: str = "",
    requires: dict[str, str | tuple[str, ...]] | None = None,
) -> Any:
    """A value option that consumes a following argument (`--backend docker`).

    The long flag `--<name>` is inferred from the attribute name; `extra_flags` are
    additional spellings (a short form, or aliases), given as a single flag or an
    iterable: `verbosity: str = option("-v", ...)` accepts both `-v` and
    `--verbosity`. Pass `name` to declare the option as data rather than as a class
    attribute. `requires` maps another parameter to the value(s) it must have for
    this option to be valid.
    """
    return Param(
        name=name,
        flags=_as_flags(extra_flags),
        default=default,
        choices=choices,
        convert=convert,
        help=help,
        requires=requires,
    )


def flag(
    extra_flags: str | Iterable[str] | None = None,
    *,
    name: str = "",
    help: str = "",
    requires: dict[str, str | tuple[str, ...]] | None = None,
) -> Any:
    """A boolean switch that takes no value, defaulting False.

    The long flag `--<name>` is inferred from the attribute name; `extra_flags` are
    additional spellings (a short form, or aliases), given as a single flag or an
    iterable. Pass `name` to declare the flag as data rather than as a class
    attribute. `requires` maps another parameter to the value(s) it must have for this
    flag to be valid.
    """
    return Param(
        name=name,
        flags=_as_flags(extra_flags),
        default=False,
        is_flag=True,
        help=help,
        requires=requires,
    )


def positional(
    help: str = "",
    name: str = "",
    default: T | None = None,
    convert: Callable[[str], T] | None = None,
    many: bool = False,
    required: bool = True,
    requires: dict[str, str | tuple[str, ...]] | None = None,
) -> Any:
    """A positional argument (command-line only).

    `many=True` collects zero or more values into a list; `required=False` makes a
    single positional optional (falling back to `default`). Pass `name` to declare it
    as data rather than as a class attribute. `requires` maps another parameter to the
    value(s) it must have for this one to be valid.
    """
    return Param(
        name=name,
        positional=True,
        many=many,
        required=required,
        default=default,
        convert=convert,
        help=help,
        requires=requires,
    )


def remainder(help: str = "") -> Any:
    """Everything after `--` (or the trailing positionals), captured verbatim.

    Command-line only; used for `exec` passthrough.
    """
    return Param(remainder=True, default=[], help=help)


def params_of(cls: type) -> list[Param]:
    """The parameters declared on `cls` and its bases, in declaration order.

    Base classes come first (so the flow-down globals lead), then the class's own
    parameters; a name declared again in a subclass overrides the inherited one.
    Finally any `extra_options` are appended, unless a name conflict is found.
    """
    found: dict[str, Param] = {}
    for klass in reversed(cls.__mro__):
        for name, value in vars(klass).items():
            if isinstance(value, Param):
                found[name] = value
    for param in getattr(cls, "extra_options", ()):
        found.setdefault(param.name, param)
    return list(found.values())


def check_requires(params: Iterable[Param], values: Mapping[str, Any]) -> str | None:
    """The first unmet cross-parameter requirement in `params`, or None.

    A parameter's `requires` maps another parameter to the value(s) it must have. It is
    enforced only when the parameter is actually set (its resolved value differs from
    its default), so an unset option imposes no requirement. A required value may be a
    tuple of allowed values. When the value of the targeted parameter is a list, the
    check passes if any of the required values appears in the list.
    """
    params = list(params)
    by_name = {param.name: param for param in params}
    for param in params:
        if not param.requires:
            continue
        if values.get(param.name) == param.default:
            continue  # not set, so its requirements do not apply
        for required_name, required in param.requires.items():
            target = values.get(required_name)
            allowed = required if isinstance(required, tuple) else (required,)
            if isinstance(target, (list, tuple, set)):
                satisfied = any(value in target for value in allowed)
            else:
                satisfied = target in allowed
            if satisfied:
                continue
            return _requirement_error(
                param, by_name.get(required_name), required, target
            )
    return None


def _requirement_error(
    param: Param,
    required_param: Param | None,
    required: str | tuple[str, ...],
    target: Any,
) -> str:
    """A message for an unmet requirement of `param` on `required_param`."""
    this = param.flags[-1] if param.flags else param.name
    allowed = required if isinstance(required, tuple) else (required,)
    wanted = " or ".join(str(value) for value in allowed)
    required_name = required_param.name if required_param else ""
    if isinstance(target, (list, tuple, set)):
        if required_param is not None and required_param.positional:
            where = required_name
        else:
            where = "--" + required_name.replace("_", "-")
        return f"{this} requires {wanted} among {where}"
    needs = "--" + required_name.replace("_", "-")
    return f"{this} requires {needs}={wanted}"


class Action:
    """A leaf command: typed parameter attributes plus a `run` method.

    Subclass it, set `name`/`help`, declare parameters as typed class attributes
    (`option`/`flag`/`positional`/`remainder`), and implement `run`, which reads
    `self.<name>` as an ordinary typed attribute -- both its own parameters and the
    flow-down globals declared on the base.

    Construct an Action instance like a dataclass (specify attribute values with
    kwargs). Unspecified parameters/attributes fall back to their defaults.

    In addition to typed class attribute parameters, a command may contribute
    parameters as data via `extra_options`. `params_of` folds them in, so
    they parse, resolve, and populate `self.<name>` like attribute-based parameters.
    This lets a command aggregate options dynamically.
    """

    name: ClassVar[str]
    help: ClassVar[str]
    extra_options: ClassVar[tuple[Param, ...]] = ()

    def __init__(self, **values: Any) -> None:
        params = params_of(type(self))
        unknown = set(values) - {param.name for param in params}
        if unknown:
            raise TypeError(f"unexpected arguments: {', '.join(sorted(unknown))}")
        for param in params:
            if param.name in values:
                value = values[param.name]
            elif param.remainder or param.many:
                value = []  # a fresh list per instance, never a shared default
            else:
                value = param.default
            setattr(self, param.name, value)

    def run(self) -> int:
        """Do the work and return a process exit code."""
        raise NotImplementedError


class Group:
    """A node in the tree: a name, help, and its child commands and groups."""

    name: ClassVar[str]
    help: ClassVar[str]
    subcommands: ClassVar[tuple[type[Action | Group], ...]] = ()


class Cli:
    """The application: the command tree, the globals-carrying base, and `run`.

    `base` is the command base class with global parameters; every leaf command
    subclasses it. `resolve` is an optional client-supplied function to inject/
    replace parameter values.
    """

    def __init__(
        self,
        name: str,
        root: type[Group],
        base: type[Action],
        resolve: Resolver | None = None,
    ) -> None:
        self.name = name
        self.root = root
        self.base = base
        self.resolve = resolve

    def run(self, argv: Sequence[str] | None = None) -> int:
        """Parse `argv` (default `sys.argv[1:]`), resolve parameters, and dispatch.

        Returns an exit code: 0 on success; 2 for a usage error (unknown command or
        option, an invalid value, a missing positional, an unmet requirement, or when
        a subcommand is required); otherwise whatever the selected command's `run`
        returns. A help request (`-h`/`--help`) prints help and returns 0.
        """
        import sys

        from repo_scanner.cli_kit.help import render as render_help
        from repo_scanner.cli_kit.parse import parse

        args = list(sys.argv[1:] if argv is None else argv)
        parsed = parse(self.root, self.base, args, self.name)
        if parsed.error is not None:
            print(f"{parsed.prog}: {parsed.error}", file=sys.stderr)
            return 2
        if parsed.help:
            print(render_help(parsed.node, parsed.scope, parsed.prog))
            return 0
        if parsed.command is None:  # stopped at a group; a subcommand is required
            print(render_help(parsed.node, parsed.scope, parsed.prog), file=sys.stderr)
            return 2
        if self.resolve is None:
            resolved = parsed.values
        else:
            resolved = self.resolve(parsed.scope, parsed.values)
        # Apply each parameter's default for anything unresolved
        values = {p.name: resolved.get(p.name, p.default) for p in parsed.scope}
        requirement = check_requires(parsed.scope, values)
        if requirement is not None:  # an unmet cross-option dependency is a usage error
            print(f"{parsed.prog}: {requirement}", file=sys.stderr)
            return 2
        return parsed.command(**values).run()
