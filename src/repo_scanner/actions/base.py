# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The action base carrying reposcan's flow-down global parameters.

Every leaf action subclasses this, so `self.backend`/`self.verbosity`/`self.uid`/
`self.image` are available (typed) in every `run`, and the globals may be given
anywhere on the command line (`--backend`, `-v`/`--verbosity`, `--uid`, `--image`),
via env (REPOSCAN_<NAME>), or in the config file. Each parameter's long flag is
inferred from its name, so only the short `-v` is spelled out here.
"""

from repo_scanner.backends import BACKEND_NAMES
from repo_scanner.cli_kit import Action as _Action
from repo_scanner.cli_kit import option
from repo_scanner.ioutil.logging import LOG_LEVELS


def _parse_uid(value: str) -> int:
    """The non-negative integer uid `value` denotes, or raise ValueError."""
    try:
        uid = int(value)
    except ValueError:
        raise ValueError(f"expected an integer, got {value!r}") from None
    if uid < 0:
        raise ValueError(f"expected a non-negative integer, got {uid}")
    return uid


def _parse_image(value: str) -> str:
    """`value` if it is a usable image reference or shorthand, or raise ValueError."""
    if value.strip():
        return value
    raise ValueError("give an image reference, 'canonical', or 'build'")


class Action(_Action):
    backend: str = option(
        default="auto",
        choices=BACKEND_NAMES,
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
        help="The container image to use: 'canonical' (default, the published "
        "image), 'build' (build locally instead of pulling), or an OCI reference.",
    )
