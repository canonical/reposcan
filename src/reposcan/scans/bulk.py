# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Scan many repositories into one database."""

import logging
import os
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from reposcan.backends import ensure_image, start_session
from reposcan.db import write as db_write
from reposcan.execution.context import RunUser
from reposcan.logging import TRANSIENT
from reposcan.result import Err, Result, is_err
from reposcan.scans import ignore
from reposcan.scans.analysis import Analysis
from reposcan.scans.registry import SCANS
from reposcan.scans.run import run_analysis

logger = logging.getLogger(__name__)

# check for SIGINT/SIGTERM in the main thread at least this often while repositories
# are being scanned
_INTERRUPT_POLLING_INTERVAL = 0.2


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
) -> dict[str, Result[Analysis]]:
    """Scan every repository in `paths`, recording each analysis in the database.

    Args:
        paths: The repositories to scan.
        scan_names: The scan types to run against each.
        db: The database to record every analysis in.
        backend: The execution backend, or None to select one.
        image: The reposcan image, or None for the default.
        user: The identity in-container processes run as.
        env: Extra environment variables for in-container processes.
        threads: How many repositories to scan at once.
        options: Scan-specific options, as the scan classes declare them.

    Returns:
        The analysis of each repository, keyed by its path, in completion order. A
        repository that could not be scanned carries an error.
    """
    # Resolved once up front so concurrent sessions reuse one build or pull rather
    # than each starting its own
    if is_err(err := ensure_image(backend, image)):
        return dict.fromkeys(paths, err)

    results: dict[str, Result[Analysis]] = {}
    cancelled = threading.Event()
    pool = ThreadPoolExecutor(max_workers=max(1, threads))
    try:
        pending = {
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
                cancelled=cancelled,
            ): path
            for path in paths
        }
        while pending:
            done, _ = wait(
                pending.keys(),
                timeout=_INTERRUPT_POLLING_INTERVAL,
                return_when=FIRST_COMPLETED,
            )
            for completed_job in done:
                path = pending.pop(completed_job)
                result = completed_job.result()
                results[path] = result
                logger.info(
                    "[%d/%d] %s", len(results), len(paths), path, extra=TRANSIENT
                )
                if is_err(result):
                    logger.error("%s: %s", path, result.msg)
    finally:
        # On SIGINT, SIGTERM, or a crash, skip all remaining scans
        cancelled.set()
        pool.shutdown(cancel_futures=True)
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
    cancelled: threading.Event,
) -> Result[Analysis]:
    """Scan one repository and record it in the database."""
    scans = [SCANS[name](**_filter_options(name, options)) for name in scan_names]
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
            return Err("could not start a session")
        analysis = run_analysis(
            session, scans, ignore_rules=rules, stream=False, cancelled=cancelled
        )
    if cancelled.is_set():
        # don't record a cancelled analysis, so the next run scans this repository again
        return Err("cancelled")
    err = db_write.write_analysis(db, analysis)
    return err if is_err(err) else analysis


def _filter_options(name: str, options: Mapping[str, Any]) -> dict[str, Any]:
    """Select the options `name`'s scan class declares."""
    from reposcan.cli_kit import collect_params

    return {
        param.name: options[param.name]
        for param in collect_params(SCANS[name])
        if param.name in options
    }
