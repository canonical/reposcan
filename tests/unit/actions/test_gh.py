# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for reposcan gh actions."""

import os
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from typing import Any
from unittest.mock import MagicMock

from reposcan.actions import gh
from reposcan.result import Err
from reposcan.scm import clone, github
from reposcan.scm.github import GithubRepository


@contextmanager
def _client(listed: Any, seen: dict[str, Any]) -> Iterator[None]:
    """Answer the client's listing with `listed`, recording its arguments in `seen`."""
    listed_is_error = getattr(listed, "error", None) is not None

    def fake_list(
        *, org: str | None = None, enterprise: str | None = None, token: str = ""
    ) -> Any:
        seen.update(org=org, enterprise=enterprise, token=token)
        return listed if listed_is_error else listed

    def fake_select(repositories: Sequence[GithubRepository], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return list(repositories)

    saved = (github.list_repositories, github.filter_repositories)
    github.list_repositories = fake_list
    github.filter_repositories = fake_select
    try:
        yield
    finally:
        github.list_repositories, github.filter_repositories = saved


def _run(command: gh.GhAction) -> tuple[int, str]:
    out = StringIO()
    with redirect_stdout(out):
        code = command.run()
    return code, out.getvalue()


def test_an_entity_is_required() -> None:
    seen: dict[str, Any] = {}
    with _client([], seen):
        assert _run(gh.ListGhRepos())[0] == 2
    assert seen == {}  # nothing was requested

    one = GithubRepository("acme/one", "https://h/acme/one.git", "main")
    with _client([one], seen):
        assert _run(gh.ListGhRepos(enterprise="acme-inc"))[0] == 0
    assert seen["enterprise"] == "acme-inc" and seen["org"] is None


def test_the_token_comes_from_the_environment_before_a_file() -> None:
    seen: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "token")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("  from_file\n")  # whitespace is stripped

        with _client([], seen):
            _run(gh.ListGhRepos(org="acme", token_file=path))
        assert seen["token"] == "from_file"

        os.environ["REPOSCAN_GH_TOKEN"] = "from_env"
        try:
            with _client([], seen):
                _run(gh.ListGhRepos(org="acme", token_file=path))
        finally:
            del os.environ["REPOSCAN_GH_TOKEN"]
        assert seen["token"] == "from_env"

    # An unreadable file fails rather than quietly falling back to an anonymous read.
    seen.clear()
    with _client([], seen):
        assert _run(gh.ListGhRepos(org="acme", token_file=path))[0] == 1
    assert seen == {}


def test_the_exclude_globs_are_split_and_the_filters_forwarded() -> None:
    seen: dict[str, Any] = {}
    with _client([], seen):
        _run(
            gh.ListGhRepos(
                org="acme",
                include_archived=True,
                exclude_forks=True,
                exclude=" *-mirror , docs ",
            )
        )
    assert seen["include_archived"] is True
    assert seen["include_forks"] is False
    assert seen["exclude"] == ["*-mirror", "docs"]


def test_a_failing_repository_is_retried_without_holding_up_the_rest() -> None:
    """A repository that keeps failing is given up on; the rest are unaffected."""
    one = GithubRepository("acme/one", "https://h/acme/one.git", "main")
    two = GithubRepository("acme/two", "https://h/acme/two.git", "main")
    synced = clone.LocalRepository("/w/mirrors/acme/one.git", {}, empty=False)
    results = {one: synced, two: Err("no route")}
    sync = MagicMock(side_effect=lambda repo, workspace, token: results[repo])

    saved = clone.sync_repository
    clone.sync_repository = sync
    try:
        outcomes = gh.sync_repositories([one, two], "/w", "", retries=2)
    finally:
        clone.sync_repository = saved

    assert outcomes == {one: synced, two: Err("no route")}
    tried = [call.args[0] for call in sync.call_args_list]
    assert tried.count(one) == 1
    assert tried.count(two) == 3  # the first attempt and both retries


def test_a_failed_sync_is_retried_until_it_succeeds() -> None:
    """A sync that fails once and then succeeds ends as a success."""
    repo = GithubRepository("acme/one", "https://h/acme/one.git", "main")
    synced = clone.LocalRepository("/w/mirrors/acme/one.git", {}, empty=False)
    sync = MagicMock(side_effect=[Err("Could not resolve host: github.com"), synced])

    saved = clone.sync_repository
    clone.sync_repository = sync
    try:
        outcomes = gh.sync_repositories([repo], "/w", "", retries=2)
    finally:
        clone.sync_repository = saved

    assert outcomes == {repo: synced}
    assert sync.call_count == 2


def test_a_failed_repository_fails_the_run() -> None:
    """The run exits 1 when any repository could not be mirrored."""
    one = GithubRepository("acme/one", "https://h/acme/one.git", "main")
    two = GithubRepository("acme/two", "https://h/acme/two.git", "main")
    synced = clone.LocalRepository("/w/mirrors/acme/one.git", {}, empty=False)
    command = gh.CloneGhRepos(org="acme", workspace="/w")
    command.select_repositories = MagicMock(return_value=[one, two])

    saved = gh.sync_repositories
    gh.sync_repositories = MagicMock(return_value={one: synced, two: Err("no route")})
    try:
        code = command.run()
    finally:
        gh.sync_repositories = saved

    assert code == 1


def test_an_empty_repository_does_not_fail_the_run() -> None:
    """An empty repository has nothing to scan, which is not a failure."""
    repo = GithubRepository("acme/empty", "https://h/acme/empty.git", "main")
    synced = clone.LocalRepository("/w/mirrors/acme/empty.git", {}, empty=True)
    command = gh.CloneGhRepos(org="acme", workspace="/w")
    command.select_repositories = MagicMock(return_value=[repo])

    saved = gh.sync_repositories
    gh.sync_repositories = MagicMock(return_value={repo: synced})
    try:
        code = command.run()
    finally:
        gh.sync_repositories = saved

    assert code == 0


def test_naming_repositories_replaces_discovery() -> None:
    # --repo is a clone-repos option, and it stands in for discovery rather than
    # adding to it: given one, --org is not resolved at all.
    named = [GithubRepository("acme/one", "https://h/acme/one.git", "main")]
    fetch_named = MagicMock(return_value=named)
    list_all = MagicMock()

    saved = (github.fetch_named_repositories, github.list_repositories)
    github.fetch_named_repositories = fetch_named
    github.list_repositories = list_all
    try:
        command = gh.CloneGhRepos(org="acme", repo=["acme/one"], workspace="/w")
        selected = command.select_repositories("")
    finally:
        github.fetch_named_repositories, github.list_repositories = saved

    assert selected == named
    fetch_named.assert_called_once_with(["acme/one"], "")
    list_all.assert_not_called()
