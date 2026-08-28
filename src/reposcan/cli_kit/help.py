# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Help and usage rendering for a node of the command tree."""

from __future__ import annotations

from reposcan.cli_kit.spec import Action, Group, Param


def render(node: type[Action | Group], scope: list[Param], prog: str) -> str:
    """Help text for `node`: usage, description, options, and subcommands."""
    options = [p for p in scope if not p.positional and not p.remainder]
    positionals = [p for p in scope if p.positional or p.remainder]
    is_group = isinstance(node, type) and issubclass(node, Group)
    children = getattr(node, "subcommands", ()) if is_group else ()

    parts = [prog]
    if options:
        parts.append("[options]")
    if children:
        parts.append("<command>")
    for param in positionals:
        parts.append(_usage_token(param))
    lines = [f"usage: {' '.join(parts)}", "", node.help]

    if children:
        lines += ["", "commands:"]
        width = max(len(c.name) for c in children)
        for child in children:
            lines.append(f"  {child.name:<{width}}  {child.help}")
    if positionals:
        lines += ["", "arguments:"]
        width = max(len(p.name) for p in positionals)
        for param in positionals:
            lines.append(f"  {param.name:<{width}}  {param.help}")
    if options:
        lines += ["", "options:"]
        rendered = [(_option_flags(p), p) for p in options]
        width = max(len(flags) for flags, _ in rendered)
        for flags, param in rendered:
            lines.append(f"  {flags:<{width}}  {param.help}")
    return "\n".join(lines)


def _usage_token(param: Param) -> str:
    if param.remainder:
        return "[-- args ...]"
    if param.many:
        return f"[{param.name} ...]"
    if not param.required:
        return f"[{param.name}]"
    return f"<{param.name}>"


def _option_flags(param: Param) -> str:
    flags = ", ".join(param.flags)
    if param.takes_cli_value:
        placeholder = "{" + ",".join(param.choices) + "}" if param.choices else "VALUE"
        return f"{flags} {placeholder}"
    return flags
