# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scanned repository's identity and git state.

A scan records which repository it covered and where in that repository's history it
sat, so a long-lived report database can tell one project's findings from another's
and place a scan relative to its neighbours. Everything here is read-only: it runs
git in the execution context exactly as `gitignore.IgnoredPaths` does, and a target
that is not a git working tree yields an identity carrying only its directory name.
"""

import logging
import posixpath
from dataclasses import dataclass

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult

logger = logging.getLogger(__name__)

_SCHEMES = ("https://", "http://", "ssh://", "git://", "ftp://", "ftps://", "file://")

# strongest first.
_REPO_IDENTITY_PROPERTIES = ("label", "root_commit", "origin")


@dataclass(frozen=True)
class ProjectIdentity:
    """Identifies a repository.

    `name` is the target's directory name. `root_commit` is what it sounds like.
    `origin` is the normalized remote url. `label` is an explicit assertion from
    the caller and overrules the rest.
    """

    name: str
    root_commit: str = ""
    origin: str = ""
    label: str = ""

    def matches(self, other: "ProjectIdentity") -> tuple[bool, str]:
        """Whether this Identity matches another, and which signal decided it.

        Takes the first property present on both.

        Args:
            other: The identity to compare against.

        Returns:
            The verdict, and the signal it came from. The caller logs the signal,
            because agreement on a directory name alone deserves a warning.
        """
        for signal in _REPO_IDENTITY_PROPERTIES:
            ours, theirs = getattr(self, signal), getattr(other, signal)
            if ours and theirs:
                return ours == theirs, signal
        if self.has_signal_other_than_name() or other.has_signal_other_than_name():
            return False, "name"
        return bool(self.name) and self.name == other.name, "name"

    def has_signal_other_than_name(self) -> bool:
        """Whether this identity carries any signal better than its directory name."""
        return bool(self.label or self.root_commit or self.origin)


@dataclass(frozen=True)
class RepositoryState:
    """A scanned repository's git state.

    Every field past `identity` is empty or false when the target is not a git working
    tree. `dirty` says the working tree differed from `commit_sha`, which means the sha
    does not describe what was actually scanned. `shallow` indicates truncated history.

    Committer dates are deliberately ignored; they're unreliable.
    """

    identity: ProjectIdentity
    commit_sha: str = ""
    branch: str = ""
    dirty: bool = False
    shallow: bool = False


def read_repository_state(
    ctx: ExecutionContext, target: str, label: str = ""
) -> RepositoryState:
    """The identity and git state of `target`, as seen from `ctx`.

    Args:
        ctx: The started context to run git in.
        target: The repository path as seen in the context.
        label: An explicit project label from the caller, or empty.

    Returns:
        The state. A target that is not a git working tree, or a context without git,
        yields an identity holding only the directory name.
    """
    name = posixpath.basename(target.rstrip("/"))
    commit_sha = _git(ctx, target, "rev-parse", "HEAD")
    if commit_sha is None:
        return RepositoryState(ProjectIdentity(name=name, label=label))
    branch = _git(ctx, target, "rev-parse", "--abbrev-ref", "HEAD") or ""
    roots = _git(ctx, target, "rev-list", "--max-parents=0", "HEAD") or ""
    origin = _git(ctx, target, "remote", "get-url", "origin") or ""
    return RepositoryState(
        identity=ProjectIdentity(
            name=name,
            # Grafted histories have several roots, so they are compared as a set.
            root_commit=",".join(sorted(roots.split())),
            origin=normalize_origin(origin),
            label=label,
        ),
        commit_sha=commit_sha,
        # A detached HEAD reports itself as "HEAD", which names no branch.
        branch="" if branch == "HEAD" else branch,
        dirty=bool(_git(ctx, target, "status", "--porcelain")),
        shallow=_git(ctx, target, "rev-parse", "--is-shallow-repository") == "true",
    )


def normalize_origin(url: str) -> str:
    """A remote url reduced to a comparable form.

    Drops the scheme, any credentials or ssh user, a port, and a trailing `.git`, and
    lowercases the host, so the ssh and https urls for one repository compare equal.

    Args:
        url: The remote url as git reports it.

    Returns:
        The comparable form, or an empty string for an empty url.
    """
    text = url.strip()
    if not text:
        return ""
    for scheme in _SCHEMES:
        text = text.removeprefix(scheme)
    # Remove ssh url user and/or https url credentials
    if "@" in text:
        text = text.split("@", 1)[1]
    # scp-style "host:owner/repo" names the same thing as "host/owner/repo", but a
    # numeric part after the colon is a port rather than the start of the path.
    host, colon, rest = text.partition(":")
    if colon:
        port, slash, remainder = rest.partition("/")
        text = f"{host}/{remainder}" if port.isdigit() and slash else f"{host}/{rest}"
    text = text.rstrip("/").removesuffix(".git")
    host, slash, path = text.partition("/")
    return f"{host.lower()}{slash}{path}"


def _git(ctx: ExecutionContext, target: str, *args: str) -> str | None:
    """The stripped stdout of a git command run in `target`, or None if it failed."""
    result = ctx.run(["git", *args], cwd=target)
    if not (isinstance(result, ExecResult) and result.exit_code == 0):
        return None
    return result.stdout.strip()
