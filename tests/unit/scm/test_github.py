# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the GitHub module."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import requests

from reposcan.execution.process import Failure
from reposcan.scm import github
from reposcan.scm.github import list_repositories


@dataclass
class _Response:
    status_code: int = 200
    body: Any = ()
    headers: dict[str, str] = field(default_factory=dict)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        return self.body


class _FakeSession:
    """A requests.Session answering from a queue, recording what it was asked."""

    def __init__(self, responses: tuple[Any, ...]) -> None:
        self._responses = list(responses)
        self.urls: list[str] = []
        self.bodies: list[Any] = []
        self.slept: list[float] = []

    def mount(self, prefix: str, adapter: Any) -> None:
        return None

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json: Any = None,
        timeout: float = 0,
    ) -> Any:
        self.urls.append(url)
        self.bodies.append(json)
        answer = self._responses.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@contextmanager
def _answering(*responses: Any) -> Iterator[_FakeSession]:
    """Answer each request from `responses`; record sleeps rather than taking them."""
    fake = _FakeSession(responses)
    session, sleep = requests.Session, github.time.sleep
    requests.Session = lambda: fake  # type: ignore[assignment,misc]
    github.time.sleep = fake.slept.append
    try:
        yield fake
    finally:
        requests.Session = session  # type: ignore[misc]
        github.time.sleep = sleep


def _payload(name: str) -> dict[str, str]:
    return {
        "full_name": f"acme/{name}",
        "clone_url": f"https://github.com/acme/{name}.git",
        "default_branch": "main",
    }


def test_pagination_follows_the_link_header_and_skips_unusable_entries() -> None:
    # The url may itself contain a comma, so the header is not split on one; an entry
    # naming no clone url is skipped rather than failing the whole page.
    link = '<https://api.github.com/x?a=1,2&page=2>; rel="next"'
    first = _Response(
        body=[_payload("one"), {"full_name": "acme/x"}], headers={"Link": link}
    )
    with _answering(first, _Response(body=[_payload("two")])) as fake:
        listed = list_repositories(org="acme")
    assert not isinstance(listed, Failure)
    assert [repo.full_name for repo in listed] == ["acme/one", "acme/two"]
    assert fake.urls[1] == "https://api.github.com/x?a=1,2&page=2"


def test_every_failure_becomes_a_failure_naming_its_cause() -> None:
    limit = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1700"}
    cases = [
        (_Response(404), "no such organization"),
        (_Response(403, headers=limit), "rate limit exhausted; resets at 1700"),
        # SSO enforcement answers 403, and its message is the whole remedy.
        (_Response(403, body={"message": "SAML enforced"}), "SAML enforced"),
        (requests.ConnectionError("no route"), "could not reach"),
    ]
    for answer, expected in cases:
        with _answering(answer) as fake:
            listed = list_repositories(org="acme")
        assert isinstance(listed, Failure) and expected in listed.reason
        assert fake.slept == []  # none of these is worth waiting out

    # the graphql half fails the same way, for an unknown slug or a rejected query
    for body, expected in (
        ({"data": {"enterprise": None}}, "no such enterprise"),
        ({"errors": [{"message": "Bad credentials"}]}, "Bad credentials"),
    ):
        with _answering(_Response(body=body)):
            listed = list_repositories(enterprise="acme-inc")
        assert isinstance(listed, Failure) and expected in listed.reason


def test_a_secondary_rate_limit_is_waited_out_then_eventually_given_up_on() -> None:
    # Unlike a primary limit, GitHub names a short delay and expects it honoured.
    slow = _Response(403, headers={"Retry-After": "5"})
    with _answering(slow, _Response(body=[_payload("one")])) as fake:
        listed = list_repositories(org="acme")
    assert fake.slept == [5.0]
    assert not isinstance(listed, Failure)

    with _answering(_Response(403, headers={"Retry-After": "86400"}), _Response()) as f:
        list_repositories(org="acme")
    assert f.slept == [60.0]  # capped, however long GitHub asks for

    with _answering(slow, slow, slow) as fake:
        listed = list_repositories(org="acme")
    assert isinstance(listed, Failure) and "times in a row" in listed.reason


def test_an_enterprise_is_read_through_its_organizations() -> None:
    # REST has no enterprise-to-repositories route, so the enterprise is resolved to
    # its organizations over GraphQL and each listed over REST.
    page = {"nodes": [{"login": "one"}], "pageInfo": {"hasNextPage": False}}
    enterprise = {"data": {"enterprise": {"organizations": page}}}
    with _answering(_Response(body=enterprise), _Response(body=[_payload("a")])) as f:
        listed = list_repositories(org="one", enterprise="acme-inc", token="s3cret")
    assert not isinstance(listed, Failure)
    assert [repo.full_name for repo in listed] == ["acme/a"]
    assert f.bodies[0]["variables"] == {"slug": "acme-inc", "after": None}
    assert len(f.urls) == 2  # the graphql query, then one repo listing
