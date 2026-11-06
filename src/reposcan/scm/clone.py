# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage local copies of remote repositories.

Each repository is stored as a bare mirror and checked out as a worktree.
"""

import base64
import logging
import os
import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from reposcan.execution.process import run_process
from reposcan.output import format_size
from reposcan.result import Err, Result, get_value, is_err

if TYPE_CHECKING:  # github needs the service extra; the annotation does not
    from reposcan.scm.github import GithubRepository

logger = logging.getLogger(__name__)

MIRROR_DIR = "mirrors"
WORKTREE_DIR = "worktrees"

# Fail a transfer that drops below this many bytes per second for this many seconds.
# Passed to native git-supported env vars.
_LOW_SPEED_BYTES = "1000"
_LOW_SPEED_SECONDS = "60"


@dataclass
class LocalRepository:
    """Metadata for a locally-mirrored repository."""

    mirror_path: str
    worktree_paths: dict[str, str]  # ref -> path
    empty: bool


def sync_repository(
    repo: "GithubRepository", workspace: str, token: str = ""
) -> Result[LocalRepository]:
    """Sync (clone or update) a local copy of `repo`.

    Args:
        repo: The repository to sync.
        workspace: The local storage directory.
        token: An authentication token, or empty to clone anonymously.

    Returns:
        LocalRepository, or an Err representing a git failure.
    """
    url, name, size = repo.clone_url, repo.full_name, repo.size
    workspace = os.path.abspath(workspace)
    mirror_dir = os.path.join(workspace, MIRROR_DIR, f"{name}.git")
    worktree_dir = os.path.join(workspace, WORKTREE_DIR, name)
    env = _build_git_environment(url, token)

    # If a previous clone attempt failed non-atomically (e.g., power loss, kill -9),
    # the local mirror path may exist in an invalid state. If the `git` CLI reports
    # no commits (or fails to read the repo at all) but GitHub reports a non-empty repo
    # the local copy is removed and a new mirror is created from scratch.
    if (
        repo.size
        and os.path.isdir(mirror_dir)
        and not get_value(_has_commits(mirror_dir))
    ):
        logger.warning(
            "%s: local mirror is empty or broken, removing it before re-cloning",
            name,
        )
        if is_err(err := _remove_dirs(mirror_dir, worktree_dir)):
            return err

    if os.path.isdir(mirror_dir):
        logger.info("Updating %s", name)
        # A mirror's refspec is already forced, so this follows a rewritten history
        # instead of failing on it, and --prune drops branches deleted upstream.
        err = _git(
            ["fetch", "--all", "--prune", "--update-head-ok", "--quiet"],
            env,
            cwd=mirror_dir,
        )
    else:
        logger.info("Mirroring %s%s", name, f" ({format_size(size)})" if size else "")
        err = _make_parent(mirror_dir)
        if not is_err(err):
            err = _git(["clone", "--mirror", "--quiet", url, mirror_dir], env)

    if is_err(err):
        return err

    has_commits = _has_commits(mirror_dir)
    if is_err(has_commits):
        return has_commits

    worktrees: dict[str, str] = {}
    if repo.default_branch and has_commits:
        if is_err(err := _checkout(mirror_dir, worktree_dir, repo.default_branch)):
            return err
        worktrees[repo.default_branch] = worktree_dir
    else:
        logger.debug("%s: synced repository is empty or has no default branch", name)

    return LocalRepository(mirror_dir, worktrees, empty=(not has_commits))


def _remove_dirs(*directories: str) -> Result[None]:
    """Delete `directories`, ignoring any that do not exist."""
    for path in directories:
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return Err(f"could not remove {path}: {exc}")
    return None


def _has_commits(mirror: str) -> Result[bool]:
    """Whether the `git` CLI detects commits within `mirror` (a directory path).

    Commits are _not_ filtered to HEAD or the default branch. Any commit in any ref
    is accepted.

    Returns:
        Whether it has one, or an Err when git can't read the mirror, so a broken
        mirror is reported as a failure rather than passed off as an empty repository.
    """
    run = run_process(["git", "for-each-ref", "--count=1"], cwd=mirror)
    if is_err(run):
        return run
    if run.exit_code != 0:
        return Err(f"git for-each-ref failed: {run.stderr.strip()}")
    return bool(run.stdout.strip())


def _checkout(mirror: str, worktree: str, ref: str) -> Result[None]:
    """Check out `mirror`'s worktree, or reset and clean the existing checkout."""
    if os.path.isdir(worktree):
        if is_err(err := _git(["reset", "--hard", ref, "--quiet"], cwd=worktree)):
            return err
        return _git(["clean", "-ffdxq"], cwd=worktree)

    if is_err(err := _make_parent(worktree)):
        return err

    return _git(["worktree", "add", "--quiet", worktree, ref], cwd=mirror)


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
    if is_err(result):
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
