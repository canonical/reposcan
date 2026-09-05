# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage local copies of remote repositories.

Each repository is stored as a bare mirror and checked out as a worktree.
"""

import base64
import logging
import os
from urllib.parse import urlsplit

from reposcan.execution.process import run_process
from reposcan.result import Err, Result, get_value, is_err

logger = logging.getLogger(__name__)

MIRROR_DIR = "mirrors"
WORKTREE_DIR = "worktrees"

# Fail a transfer that drops below this many bytes per second for this many seconds.
# Passed to native git-supported env vars.
_LOW_SPEED_BYTES = "1000"
_LOW_SPEED_SECONDS = "60"


def sync_repository(
    url: str, workspace: str, name: str, token: str = ""
) -> Result[str]:
    """Sync (clone or update) a local copy of `url`.

    Args:
        url: The repository's clone url.
        workspace: The local storage directory.
        name: The repository's `owner/name`.
        token: An authentication token, or empty to clone anonymously.

    Returns:
        The worktree path to scan, or an Err naming the git step that failed.
    """
    mirror = os.path.join(workspace, MIRROR_DIR, f"{name}.git")
    worktree = os.path.join(workspace, WORKTREE_DIR, name)
    env = _build_git_environment(url, token)

    if os.path.isdir(mirror):
        logger.info("updating %s", name)
        # A mirror's refspec is already forced, so this follows a rewritten history
        # instead of failing on it, and --prune drops branches deleted upstream.
        err = _git(
            ["fetch", "--all", "--prune", "--update-head-ok", "--quiet"],
            env,
            cwd=mirror,
        )
    else:
        logger.info("mirroring %s", name)
        err = _make_parent(mirror)
        if not is_err(err):
            err = _git(["clone", "--mirror", "--quiet", url, mirror], env)
    return err if is_err(err) else _checkout(mirror, worktree)


def _checkout(mirror: str, worktree: str) -> Result[str]:
    """Check out `mirror`'s worktree, or reset and clean the existing checkout."""
    if os.path.isdir(worktree):
        # HEAD already points at the updated ref, since the worktree shares the
        # mirror's refs; this is what moves the files to match it.
        if is_err(err := _git(["reset", "--hard", "--quiet"], cwd=worktree)):
            return err
        err = _git(["clean", "-ffdxq"], cwd=worktree)
        return err if is_err(err) else worktree

    head = get_value(
        run_process(["git", "symbolic-ref", "--short", "HEAD"], cwd=mirror)
    )
    if head is None or head.exit_code != 0:
        return Err(f"could not read the default branch of {mirror}")
    if is_err(err := _make_parent(worktree)):
        return err
    err = _git(
        ["worktree", "add", "--quiet", worktree, head.stdout.strip()], cwd=mirror
    )
    return err if is_err(err) else worktree


def _make_parent(path: str) -> Result[None]:
    """Create the directory `path` will sit in."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except OSError as exc:
        return Err(f"could not create {os.path.dirname(path)}: {exc}")
    return None


def _git(
    args: list[str], env: dict[str, str] | None = None, *, cwd: str | None = None
) -> Result[None]:
    """Run a git command."""
    result = run_process(["git", *args], cwd=cwd, env=env)
    if isinstance(result, Err):
        return result
    if result.exit_code != 0:
        return Err(f"git {args[0]} failed: {result.stderr.strip()}")
    return None


def _build_git_environment(url: str, token: str) -> dict[str, str]:
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
