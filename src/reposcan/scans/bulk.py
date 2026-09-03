# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Scan many repositories into one database."""

import logging
import os
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from reposcan.backends import ensure_image, start_session
from reposcan.db import write as db_write
from reposcan.execution.context import RunUser
from reposcan.execution.process import Failure
from reposcan.logging import TRANSIENT
from reposcan.scans import ignore
from reposcan.scans.analysis import Analysis
from reposcan.scans.registry import SCANS
from reposcan.scans.run import run_analysis

logger = logging.getLogger(__name__)


def scan_repositories(
    paths: Sequence[str],
    scan_names: Sequence[str],
    *,
    db: str,
    backend: str | None = None,
    image: str | None = None,
    user: RunUser | None = None,
    env: Mapping[str, str] | None = None,
    threads: int = 1,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Analysis | Failure]:
    """Scan every repository in `paths`, recording each analysis in the database.

    Args:
        paths: The repositories to scan.
        scan_names: The scan types to run against each.
        db: The database to record every analysis in.
        backend: The execution backend, or None to select one.
        image: The tool image, or None for the default.
        user: The identity in-container processes run as.
        env: Extra environment variables for in-container processes.
        threads: How many repositories to scan at once.
        options: Scan-specific options, as the scan classes declare them.

    Returns:
        The analysis of each repository, keyed by its path, in completion order. A
        repository that could not be scanned carries a Failure rather than raising.
    """
    # Resolved once up front so concurrent sessions reuse one build or pull rather
    # than each starting its own
    unavailable = ensure_image(backend, image)
    if unavailable is not None:
        return dict.fromkeys(paths, unavailable)

    results: dict[str, Analysis | Failure] = {}
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        running = {
            pool.submit(
                _scan_one,
                path,
                scan_names,
                db=db,
                backend=backend,
                image=image,
                user=user,
                env=env,
                options=options or {},
            ): path
            for path in paths
        }
        for done, future in enumerate(as_completed(running), start=1):
            path = running[future]
            result = future.result()
            logger.info("[%d/%d] %s", done, len(paths), path, extra=TRANSIENT)
            if isinstance(result, Failure):
                logger.error("%s: %s", path, result.reason)
            results[path] = result
    return results


def _scan_one(
    path: str,
    scan_names: Sequence[str],
    *,
    db: str,
    backend: str | None,
    image: str | None,
    user: RunUser | None,
    env: Mapping[str, str] | None,
    options: Mapping[str, Any],
) -> Analysis | Failure:
    """Scan one repository and record it in the database."""
    scans = [SCANS[name](**_options_for(name, options)) for name in scan_names]
    rules: list[ignore.IgnoreRule] = []
    ignore_path = os.path.join(path, ignore.DEFAULT_IGNORE_FILE)
    if os.path.isfile(ignore_path):
        rules, errors = ignore.load(ignore_path)
        for message in errors:
            logger.warning("%s: %s", path, message)
    with start_session(
        backend,
        mount_source=path,
        image=image,
        user=user,
        env=env,
    ) as session:
        if not session.ok:
            return Failure(reason="could not start a session")
        analysis = run_analysis(session, scans, ignore_rules=rules, stream=False)
    written = db_write.analysis(db, analysis)
    return written if isinstance(written, Failure) else analysis


def _options_for(name: str, options: Mapping[str, Any]) -> dict[str, Any]:
    """Pick the options `name`'s scan class declares from those given."""
    from reposcan.cli_kit import params_of

    return {
        param.name: options[param.name]
        for param in params_of(SCANS[name])
        if param.name in options
    }
