# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read repository metadata from GitHub's REST and GraphQL APIs."""

import fnmatch
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from reposcan.logging import TRANSIENT
from reposcan.result import Err, Result, is_err

logger = logging.getLogger(__name__)

_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="next"')

_ENTERPRISE_ORGS_QUERY = """
query($slug: String!, $after: String) {
  enterprise(slug: $slug) {
    organizations(first: 100, after: $after) {
      nodes { login }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""

_GITHUB_API = "https://api.github.com"
_GITHUB_GRAPHQL = "https://api.github.com/graphql"
_API_VERSION = "2022-11-28"
_PER_PAGE = 100
_TIMEOUT = 30.0
_MAX_PAGES = 250  # A ceiling on pagination

# GitHub sends secondary rate limit notifications with a Retry-After (usually <= 60s).
# A primary limit sets x-ratelimit-remaining to 0 and resets after >= 1h.
_RETRY_ATTEMPTS = 3
_MAX_RETRY_WAIT = 60.0

# Transient server errors, which urllib3 retries transparently with backoff.
_RETRY_STATUSES = (
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
)

# What a rate limit is answered with. 403 may also indicate an auth error.
# (GitHub's use of 403 for rate-limiting is non-standard)
_RATE_LIMIT_STATUSES = (HTTPStatus.FORBIDDEN, HTTPStatus.TOO_MANY_REQUESTS)


@dataclass(frozen=True)
class Repository:
    """A repository as GitHub describes it."""

    full_name: str  # "canonical/reposcan"
    clone_url: str  # https, must never includes credentials
    default_branch: str
    archived: bool = False
    fork: bool = False
    disabled: bool = False

    @classmethod
    def from_dict(cls, dict: Mapping[str, Any]) -> "Repository | None":
        """Parse repository metadata from `dict`."""
        full_name = str(dict.get("full_name") or "")
        clone_url = str(dict.get("clone_url") or "")
        if not full_name or not clone_url:
            return None
        return cls(
            full_name=full_name,
            clone_url=clone_url,
            default_branch=str(dict.get("default_branch") or ""),
            archived=bool(dict.get("archived")),
            fork=bool(dict.get("fork")),
            disabled=bool(dict.get("disabled")),
        )


def filter_repositories(
    repositories: Sequence[Repository],
    *,
    include_archived: bool = False,
    include_forks: bool = True,
    exclude: Sequence[str] = (),
) -> list[Repository]:
    """Filter repositories based on provided criteria.

    A disabled repository is never scanned: it cannot be cloned. An archived one is
    skipped unless asked for; a fork is kept unless excluded. `exclude` holds globs
    matched against the full name.
    """
    selected: list[Repository] = []
    for repository in repositories:
        if repository.disabled:
            continue
        if repository.archived and not include_archived:
            continue
        if repository.fork and not include_forks:
            continue
        if any(fnmatch.fnmatch(repository.full_name, glob) for glob in exclude):
            continue
        selected.append(repository)
    return selected


def list_repositories(
    *, org: str | None = None, enterprise: str | None = None, token: str = ""
) -> Result[list[Repository]]:
    """List the repositories in `org`, `enterprise`, or both.

    Args:
        org: A GH organization.
        enterprise: A GH enterprise. Requires `token`: fetching an enterprise's
            organizations needs the GraphQL API, which refuses anonymous clients.
        token: A token to authenticate with, or empty. Unauthenticated requests
            can only list public repos and have a lower rate limit.

    Returns:
        The discovered repositories, or an Err on the first request failure.
    """
    headers = _build_headers(token)
    with _open_session() as session:
        orgs: list[str] = []
        if enterprise:
            logger.info("resolving the organizations in %s", enterprise)
            found = get_enterprise_organizations(session, headers, enterprise)
            if isinstance(found, Err):
                return found
            orgs.extend(found)
        if org:
            orgs.append(org)

        repositories: dict[str, Repository] = {}
        for found_org in dict.fromkeys(orgs):  # an org may be named twice
            logger.info("listing repositories in %s", found_org)
            listed = get_org_repositories(session, headers, found_org)
            if isinstance(listed, Err):
                return listed
            for repository in listed:
                repositories.setdefault(repository.full_name, repository)
    return list(repositories.values())


def get_repositories(names: Sequence[str], token: str = "") -> Result[list[Repository]]:
    """Fetch each repository named `owner/name`.

    Args:
        names: The repositories to fetch.
        token: A token to authenticate with, or empty.

    Returns:
        The repositories, or an Err  on first fetch failure.
    """
    headers = _build_headers(token)
    repositories: dict[str, Repository] = {}
    with _open_session() as session:
        for full_name in dict.fromkeys(names):
            found = get_repository(session, headers, full_name)
            if isinstance(found, Err):
                return found
            repositories.setdefault(found.full_name, found)
    return list(repositories.values())


def _build_headers(token: str) -> dict[str, str]:
    """Build the headers every request to GitHub carries."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": _API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _open_session() -> "requests.Session":
    """Open a session that retries transient server errors with backoff.

    Rate limits are not handled here.
    """
    session = requests.Session()
    session.mount(
        "https://",
        HTTPAdapter(
            max_retries=Retry(
                total=_RETRY_ATTEMPTS,
                backoff_factor=1.0,
                status_forcelist=_RETRY_STATUSES,
                allowed_methods=frozenset({"GET", "POST"}),
            )
        ),
    )
    return session


def get_repository(
    session: "requests.Session", headers: dict[str, str], full_name: str
) -> Result[Repository]:
    """Fetch `owner/name`."""
    response = _request(session, "GET", f"{_GITHUB_API}/repos/{full_name}", headers)
    if isinstance(response, Err):
        return response
    if response.status_code == HTTPStatus.NOT_FOUND:
        return Err(f"no such repository: {full_name}")
    if is_err(err := _validate_response(response)):
        return err
    try:
        payload = response.json()
    except ValueError as exc:
        return Err(f"{full_name} did not return JSON: {exc}")
    repository = Repository.from_dict(payload)
    if repository is None:
        return Err(f"{full_name} named no clone url")
    return repository


def get_org_repositories(
    session: "requests.Session", headers: dict[str, str], org: str
) -> Result[list[Repository]]:
    """Fetch every repository in `org`.

    Stops after `_MAX_PAGES` pages, warning that the listing is incomplete.
    """
    repositories: list[Repository] = []
    url = f"{_GITHUB_API}/orgs/{org}/repos?per_page={_PER_PAGE}"
    for _ in range(_MAX_PAGES):
        response = _request(session, "GET", url, headers)
        if isinstance(response, Err):
            return response
        if response.status_code == HTTPStatus.NOT_FOUND:
            return Err(f"no such organization: {org}")
        if is_err(err := _validate_response(response)):
            return err
        try:
            payloads = response.json()
        except ValueError as exc:
            return Err(f"{url} did not return JSON: {exc}")
        if not isinstance(payloads, list):
            return Err(f"{url} did not return a list of repositories")
        for payload in payloads:
            repository = Repository.from_dict(payload)
            if repository is not None:
                repositories.append(repository)
        next_url = _find_next_page(response.headers.get("Link", ""))
        if next_url is None:
            break
        logger.info(
            "%s: %d repositories so far", org, len(repositories), extra=TRANSIENT
        )
        url = next_url
    else:
        logger.warning(
            "stopping after %d pages; %s lists more repositories than reposcan will "
            "page through",
            _MAX_PAGES,
            org,
        )
    return repositories


def get_enterprise_organizations(
    session: "requests.Session", headers: dict[str, str], enterprise: str
) -> Result[list[str]]:
    """Fetch every organization in `enterprise`.

    GraphQL rather than REST because the REST API exposes no route from an enterprise
    to its organizations or repositories. Stops after `_MAX_PAGES` pages, warning that
    the listing is incomplete.
    """
    orgs: list[str] = []
    cursor: str | None = None
    for _ in range(_MAX_PAGES):
        body = {
            "query": _ENTERPRISE_ORGS_QUERY,
            "variables": {"slug": enterprise, "after": cursor},
        }
        response = _request(session, "POST", _GITHUB_GRAPHQL, headers, body)
        if isinstance(response, Err):
            return response
        if response.status_code == HTTPStatus.NOT_FOUND:
            return Err(f"no such enterprise: {enterprise}")
        if is_err(err := _validate_response(response)):
            return err
        try:
            payload = response.json()
        except ValueError as exc:
            return Err(f"{_GITHUB_GRAPHQL} did not return JSON: {exc}")
        if payload.get("errors"):
            detail = payload["errors"][0].get("message", "unknown error")
            return Err(f"github rejected the query: {detail}")
        found = (payload.get("data") or {}).get("enterprise")
        if found is None:
            return Err(f"no such enterprise: {enterprise}")
        organizations = found.get("organizations", {})
        orgs.extend(
            str(node["login"]) for node in organizations.get("nodes") or [] if node
        )
        page = organizations.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        logger.info(
            "%s: %d organizations so far", enterprise, len(orgs), extra=TRANSIENT
        )
        cursor = page.get("endCursor")
    else:
        logger.warning(
            "stopping after %d pages of %s organizations", _MAX_PAGES, enterprise
        )
    return orgs


def _request(
    session: "requests.Session",
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
) -> "Result[requests.Response]":
    """Make an HTTP request, waiting out a rate limit GitHub asks reposcan to honour."""
    for _ in range(_RETRY_ATTEMPTS):
        try:
            response = session.request(
                method, url, headers=headers, json=body, timeout=_TIMEOUT
            )
        except requests.RequestException as exc:
            return Err(f"could not reach {url}: {exc}")
        if response.status_code not in _RATE_LIMIT_STATUSES:
            return response
        if response.headers.get("x-ratelimit-remaining") == "0":
            return response  # a primary limit, too slow to wait out
        try:
            pause = min(float(response.headers["Retry-After"]), _MAX_RETRY_WAIT)
        except (KeyError, ValueError):
            return response  # a 403 for another reason, such as SSO
        logger.warning("github asked reposcan to wait %.0fs; retrying", pause)
        time.sleep(pause)
    return Err(f"github rate limited reposcan {_RETRY_ATTEMPTS} times in a row")


def _validate_response(response: "requests.Response") -> Result[None]:
    """Validate that GitHub answered the request.

    A 404 is left to the caller, which knows what it asked for and can name it.
    """
    if response.status_code in _RATE_LIMIT_STATUSES:
        if response.headers.get("x-ratelimit-remaining") == "0":
            reset = response.headers.get("x-ratelimit-reset", "an unknown time")
            return Err(f"github rate limit exhausted; resets at {reset}")
        retry_after = response.headers.get("Retry-After")
        wait = f"; retry after {retry_after}s" if retry_after else ""
        # SAML/SSO enforcement answers 403, and its message is the whole remedy.
        return Err(
            f"github refused the request{wait}: {_parse_error_message(response)}"
        )
    if response.status_code == HTTPStatus.UNAUTHORIZED:
        return Err("github rejected the token")
    if not response.ok:
        message = _parse_error_message(response)
        return Err(f"github returned {response.status_code}: {message}")
    return None


def _parse_error_message(response: "requests.Response") -> str:
    """Parse the error message GitHub returned."""
    try:
        body = response.json()
    except ValueError:
        return response.reason or "no message"
    if isinstance(body, dict) and body.get("message"):
        return str(body["message"])
    return response.reason or "no message"


def _find_next_page(link_header: str) -> str | None:
    """Parse the `rel="next"` url from GitHub's Link header.

    Matched on the bracketed url rather than split on commas, which a url may contain.
    """
    found = _NEXT_LINK.search(link_header)
    return found.group(1) if found else None
