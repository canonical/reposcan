# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage local copies of remote repositories.

Each repository is stored as a bare mirror and checked out as a worktree.
"""

import base64
import logging
import os
import shutil
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from reposcan.execution.process import run_process
from reposcan.output import format_size
from reposcan.result import Err, Result, get_value, is_err

if TYPE_CHECKING:  # github needs the service extra; the annotation does not
    from reposcan.scm.github import Repository

logger = logging.getLogger(__name__)

MIRROR_DIR = "mirrors"
WORKTREE_DIR = "worktrees"

# Fail a transfer that drops below this many bytes per second for this many seconds.
# Passed to native git-supported env vars.
_LOW_SPEED_BYTES = "1000"
_LOW_SPEED_SECONDS = "60"


def sync_repository(
    repository: "Repository", workspace: str, token: str = ""
) -> Result[str | None]:
    """Sync (clone or update) a local copy of `repository`.

    Args:
        repository: The repository to sync. Its size, as GitHub reports it, is shown
            in the log so the big ones stand out.
        workspace: The local storage directory.
        token: An authentication token, or empty to clone anonymously.

    Returns:
        The worktree path to scan, None when the repository is empty, or an Err
        naming the git step that failed.
    """
    url, name, size = repository.clone_url, repository.full_name, repository.size
    workspace = os.path.abspath(workspace)
    mirror = os.path.join(workspace, MIRROR_DIR, f"{name}.git")
    worktree = os.path.join(workspace, WORKTREE_DIR, name)
    env = _build_git_environment(url, token)

    # A clone cut off hard (power loss, kill -9) leaves behind whatever it had, since
    # git gets no chance to clean up. The fetch below heals most of these, but not one
    # cut off before git saved where it was cloning from: that has no commits, and
    # would pass for an empty repository. GitHub reporting content gives it away. A
    # mirror git can't read at all is just as broken, so it's cloned again too: its
    # Err reads as None through get_value, the same as having no commits.
    if size and os.path.isdir(mirror) and not get_value(_has_commits(mirror)):
        logger.warning(
            "%s: local mirror has no commits but GitHub reports %s; cloning it again",
            name,
            format_size(size),
        )
        if is_err(err := _remove_local_copy(mirror, worktree)):
            return err

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
        logger.info("mirroring %s%s", name, f" ({format_size(size)})" if size else "")
        err = _make_parent(mirror)
        if not is_err(err):
            err = _git(["clone", "--mirror", "--quiet", url, mirror], env)
    if is_err(err):
        return err
    has_commits = _has_commits(mirror)
    if is_err(has_commits):
        return has_commits
    if not has_commits:
        return None
    return _checkout(mirror, worktree)


def _remove_local_copy(mirror: str, worktree: str) -> Result[None]:
    """Delete a repository's mirror, and its worktree if it has one."""
    for path in (worktree, mirror):
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return Err(f"could not remove {path}: {exc}")
    return None


def _has_commits(mirror: str) -> Result[bool]:
    """Whether `mirror` holds any commit at all.

    Asks for any ref, not for HEAD: a repository whose default branch was deleted but
    which has other branches is not empty, and failing its checkout is the right call.

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
