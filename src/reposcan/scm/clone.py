# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage local copies of remote repositories.

Each repository is stored as a bare mirror and checked out as a worktree.
"""

import base64
import logging
import os
from urllib.parse import urlsplit

from reposcan.execution.process import Failure, run_process

logger = logging.getLogger(__name__)

MIRROR_DIR = "mirrors"
WORKTREE_DIR = "worktrees"

# Fail a transfer that drops below this many bytes per second for this many seconds.
# Passed to native git-supported env vars.
_LOW_SPEED_BYTES = "1000"
_LOW_SPEED_SECONDS = "60"


def sync_repository(
    url: str, workspace: str, name: str, token: str = ""
) -> str | Failure:
    """Sync a local copy of `url` and return its local worktree path.

    Args:
        url: The repository's clone url.
        workspace: The local storage directory.
        name: The repository's `owner/name`.
        token: An authentication token.

    Returns:
        The path to scan (or a Failure).
    """
    mirror = os.path.join(workspace, MIRROR_DIR, f"{name}.git")
    worktree = os.path.join(workspace, WORKTREE_DIR, name)
    env = _git_environment(url, token)

    if os.path.isdir(mirror):
        logger.info("updating %s", name)
        # A mirror's refspec is already forced, so this follows a rewritten history
        # instead of failing on it, and --prune drops branches deleted upstream.
        failed = _git(
            ["fetch", "--all", "--prune", "--update-head-ok", "--quiet"],
            env,
            cwd=mirror,
        )
    else:
        logger.info("mirroring %s", name)
        failed = _make_parent(mirror) or _git(
            ["clone", "--mirror", "--quiet", url, mirror], env
        )
    if failed is not None:
        return failed
    return _checkout(mirror, worktree)


def _checkout(mirror: str, worktree: str) -> str | Failure:
    """Check out `mirror`'s worktree, resetting one that already exists."""
    if os.path.isdir(worktree):
        # HEAD already points at the updated ref, since the worktree shares the
        # mirror's refs; this is what moves the files to match it.
        failed = _git(["reset", "--hard", "--quiet"], cwd=worktree) or _git(
            ["clean", "-ffdxq"], cwd=worktree
        )
        return failed if failed is not None else worktree

    head = run_process(["git", "symbolic-ref", "--short", "HEAD"], cwd=mirror)
    if isinstance(head, Failure) or head.exit_code != 0:
        return Failure(reason=f"could not read the default branch of {mirror}")
    failed = _make_parent(worktree) or _git(
        ["worktree", "add", "--quiet", worktree, head.stdout.strip()], cwd=mirror
    )
    return failed if failed is not None else worktree


def _make_parent(path: str) -> Failure | None:
    """Create the directory `path` will sit in."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError as exc:
        return Failure(reason=f"could not create {os.path.dirname(path)}: {exc}")
    return None


def _git(
    args: list[str], env: dict[str, str] | None = None, *, cwd: str | None = None
) -> Failure | None:
    """Run a git command."""
    result = run_process(["git", *args], cwd=cwd, env=env)
    if isinstance(result, Failure):
        return result
    if result.exit_code != 0:
        return Failure(reason=f"git {args[0]} failed: {result.stderr.strip()}")
    return None


def _git_environment(url: str, token: str) -> dict[str, str]:
    """Build environment vars for a git command.

    Tokens are passed to git via env vars, not via urls, which git writes into
    `.git/config` and reposcan records into the database.
    """
    env = {
        **os.environ,
        # prevents interactive terminal prompts
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_HTTP_LOW_SPEED_LIMIT": _LOW_SPEED_BYTES,
        "GIT_HTTP_LOW_SPEED_TIME": _LOW_SPEED_SECONDS,
    }
    if not token:
        return env
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    origin = urlsplit(url)
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{origin.scheme}://{origin.netloc}/.extraheader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        }
    )
    return env
