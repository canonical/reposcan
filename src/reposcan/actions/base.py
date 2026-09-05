# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The action base carrying reposcan's flow-down global parameters.

Every leaf action subclasses this, so `self.backend`/`self.verbosity`/`self.uid`/
`self.image` are available (typed) in every `run`. Each parameter's long flag is
inferred from its name, so only the short `-v` is spelled out here.
"""

import re
from collections.abc import Sequence

from reposcan.backends import AUTO, BACKENDS
from reposcan.cli_kit import Action as _Action
from reposcan.cli_kit import option
from reposcan.logging import LOG_LEVELS

# A portable environment variable name, so a malformed --env is a usage error
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _parse_uid(value: str) -> int:
    """Parse `value` as a non-negative integer uid."""
    try:
        uid = int(value)
    except ValueError:
        raise ValueError(f"expected an integer, got {value!r}") from None
    if uid < 0:
        raise ValueError(f"expected a non-negative integer, got {uid}")
    return uid


def _parse_env(value: str) -> str:
    """Parse `value` as a NAME or NAME=VALUE spec."""
    name = value.partition("=")[0]
    if _ENV_NAME.fullmatch(name) is None:
        raise ValueError(f"expected NAME or NAME=VALUE, got {value!r}")
    return value


def _parse_image(value: str) -> str:
    """Parse `value` as a non-blank image reference or shorthand."""
    if value.strip():
        return value
    raise ValueError("give an image reference, 'canonical', or 'build'")


class Action(_Action):
    backend: str = option(
        default=AUTO,
        choices=(AUTO, *BACKENDS),
        help="The execution backend tools run in.",
    )
    verbosity: str = option(
        extra_flags="-v",
        default="info",
        choices=tuple(LOG_LEVELS),
        help="The lowest log level written to stderr.",
    )
    uid: int | None = option(
        convert=_parse_uid,
        help="UID for in-backend processes; unset runs as the invoking host user.",
    )
    image: str | None = option(
        convert=_parse_image,
        help="The container image to use: 'canonical' (the official "
        "image), 'build', or an OCI reference.",
    )
    env: Sequence[str] = option(
        default=(),
        many=True,
        convert=_parse_env,
        help="Pass NAME from this environment (or NAME=VALUE) to subprocess calls. "
        "Repeatable.",
    )
