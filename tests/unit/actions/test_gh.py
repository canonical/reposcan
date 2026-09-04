# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for reposcan gh actions."""

import os
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from typing import Any

from reposcan.actions import gh
from reposcan.execution.process import Failure
from reposcan.scm import github
from reposcan.scm.github import Repository


def _build_repo(name: str) -> Repository:
    return Repository(f"acme/{name}", f"https://h/acme/{name}.git", "main")


@contextmanager
def _client(listed: Any, seen: dict[str, Any]) -> Iterator[None]:
    """Answer the client's listing with `listed`, recording its arguments in `seen`."""

    def fake_list(
        *, org: str | None = None, enterprise: str | None = None, token: str = ""
    ) -> Any:
        seen.update(org=org, enterprise=enterprise, token=token)
        return listed

    def fake_get(names: Sequence[str], token: str = "") -> Any:
        seen.update(repos=list(names), token=token)
        return listed

    def fake_select(repositories: Sequence[Repository], **kwargs: Any) -> Any:
        seen.update(kwargs)
        return list(repositories)

    saved = (
        github.list_repositories,
        github.get_repositories,
        github.filter_repositories,
    )
    github.list_repositories = fake_list
    github.get_repositories = fake_get
    github.filter_repositories = fake_select
    try:
        yield
    finally:
        (
            github.list_repositories,
            github.get_repositories,
            github.filter_repositories,
        ) = saved


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

    with _client([_build_repo("one")], seen):
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


def test_one_unreachable_repository_does_not_abandon_the_rest() -> None:
    synced: list[str] = []

    def fake_sync(url: str, workspace: str, name: str, token: str = "") -> Any:
        synced.append(name)
        return (
            Failure(reason="no route") if name == "acme/two" else f"{workspace}/{name}"
        )

    saved = gh.clone.sync_repository
    gh.clone.sync_repository = fake_sync
    try:
        with _client(
            [_build_repo("one"), _build_repo("two"), _build_repo("three")], {}
        ):
            code, _ = _run(gh.CloneGhRepos(org="acme", workspace="/tmp/x"))
    finally:
        gh.clone.sync_repository = saved

    assert synced == ["acme/one", "acme/two", "acme/three"]  # it kept going
    assert code == 1  # but the run reports that something failed


def test_naming_repositories_replaces_discovery() -> None:
    # --repo is a clone-repos option, and it stands in for discovery rather than
    # adding to it: given one, --org is not resolved at all.
    seen: dict[str, Any] = {}
    saved = gh.clone.sync_repository
    gh.clone.sync_repository = lambda url, workspace, name, token="": (
        f"{workspace}/{name}"
    )
    try:
        with _client([_build_repo("discovered")], seen):
            code, _ = _run(gh.CloneGhRepos(repo=["acme/one"], workspace="/tmp/x"))
        assert code == 0  # --repo alone satisfies the entity requirement
        assert seen["repos"] == ["acme/one"]
        assert "org" not in seen

        with _client([_build_repo("discovered")], seen):
            _run(gh.CloneGhRepos(org="acme", repo=["acme/one"], workspace="/tmp/x"))
        assert seen["repos"] == ["acme/one"]
        assert "org" not in seen  # --org still not resolved
    finally:
        gh.clone.sync_repository = saved
