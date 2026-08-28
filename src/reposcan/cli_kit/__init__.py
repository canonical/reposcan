# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""cli_kit: a small, declarative command-line framework.

Declare commands as classes (`Action`/`Group`) with typed parameter attributes
(`option`/`flag`/`positional`/`remainder`), compose them into a `Cli`, and let the
engine parse and coerce argv into finished command-line values, render help, and
dispatch. A parameter the command line did not supply is filled with its default,
unless the application supplies a resolver: an optional `Cli` hook that provides
such parameters from its own sources (env, config, ...). `coerce` is exported as
a utility for such a resolver.
"""

from reposcan.cli_kit.coerce import coerce
from reposcan.cli_kit.parse import parse
from reposcan.cli_kit.spec import (
    Action,
    Cli,
    Group,
    Param,
    Resolver,
    check_requires,
    flag,
    option,
    params_of,
    positional,
    remainder,
)

__all__ = [
    "Action",
    "Cli",
    "Group",
    "Param",
    "Resolver",
    "check_requires",
    "coerce",
    "flag",
    "option",
    "params_of",
    "parse",
    "positional",
    "remainder",
]
