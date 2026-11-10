# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan scan` command.

Each scan's own options (secrets' `--mode`/`--depth`, sca's
`--include-dev-dependencies`/`--allow-code-execution`) are declared on the scan classes
and aggregated onto this command via `extra_options`.
"""

import copy
import logging
import os
from collections.abc import Iterable
from pathlib import Path

from reposcan import output
from reposcan.actions.base import Action
from reposcan.backends import start_session
from reposcan.cli_kit import Param, collect_params, flag, option, positional
from reposcan.db import write as db_write
from reposcan.execution.context import RunUser, get_host_user, resolve_env
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.result import is_err
from reposcan.scans import bulk, ignore, sarif
from reposcan.scans.analysis import Analysis
from reposcan.scans.base import SecurityScan
from reposcan.scans.registry import SCANS, parse_scan_names
from reposcan.scans.run import run_analysis
from reposcan.table import DEFAULT_WRAP_LINES

logger = logging.getLogger(__name__)

FORMATS = tuple(f.value for f in Format)

# Exit code when a scan reports a finding at or above the --fail-on level.
FINDINGS_EXIT_CODE = 3

# SARIF levels ranked for --fail-on's "at or above" threshold; a finding with no level
# counts as warning, per SARIF. 'none' is absent (rank 0), so it never fails.
_FAIL_RANK = {"note": 1, "warning": 2, "error": 3}

# One repository per processor. Scans may be CPU-bound.
_DEFAULT_SCAN_THREADS = os.cpu_count() or 1


def _aggregate_scan_options(scans: dict[str, type[SecurityScan]]) -> tuple[Param, ...]:
    """Gather every scan's options, each requiring its scan(s) to be selected.

    A scan-specific option is only meaningful when a scan that declares it is selected,
    so each aggregated option gains a `requires` that the `scans` list contain one of
    its declaring scans.
    """
    declared_by: dict[str, list[str]] = {}
    params: dict[str, Param] = {}
    for scan_name, scan_class in scans.items():
        for param in collect_params(scan_class):
            params.setdefault(param.name, param)
            declared_by.setdefault(param.name, []).append(scan_name)
    aggregated: list[Param] = []
    for name, param in params.items():
        owners = declared_by[name]
        requires = dict(param.requires or {})
        requires["scans"] = tuple(owners) if len(owners) > 1 else owners[0]
        clone = copy.copy(param)
        clone.requires = requires
        aggregated.append(clone)
    return tuple(aggregated)


class ScanCommand(Action):
    """Run one or more scan types against a repository and consolidate the results."""

    name = "scan"
    help = "Scan a repository with one or more scan types."

    scans: list[str] = positional(
        convert=parse_scan_names,
        help="Scan type(s), comma-separated: secrets, sast, iac, workflow, sca, "
        "or all (e.g. sast,secrets).",
    )
    path: str = positional(
        help="Path to the repository to scan, or with -r, the directory to search."
    )
    recursive: bool = flag("-r", help="Find and scan every git repository in PATH.")
    threads: int = option(
        default=_DEFAULT_SCAN_THREADS,
        convert=int,
        help="With -r, repositories to scan at once (default: one per processor).",
    )
    output: str | None = option(
        "-o", help="Write the report to FILE instead of stdout."
    )
    db: str | None = option(
        help="Record this analysis in the database at FILE, creating it if absent. "
        "(independent of -o)"
    )
    format: str | None = option("-f", choices=FORMATS, help="Output format.")
    limit: int = option(
        "-n",
        default=DEFAULT_ROW_LIMIT,
        convert=int,
        help="Maximum rows shown in a table.",
    )
    wrap: int = option(
        default=DEFAULT_WRAP_LINES,
        convert=int,
        help="Maximum lines one row in a table may wrap across.",
    )
    ignore_file: str | None = option(
        help=f"reposcan ignorefile (default: {ignore.DEFAULT_IGNORE_FILE}).",
    )
    no_ignore_file: bool = flag(help="Do not read any reposcan ignorefile.")
    fail_on: str = option(
        choices=("error", "warning", "note", "none"),
        default="note",
        help="Exit non-zero only for a finding at or above this level; 'none' "
        "never fails.",
    )

    extra_options = _aggregate_scan_options(SCANS)

    def run(self) -> int:
        """Run the requested scans and write the report.

        Exit codes:
            0 when nothing at or above --fail-on was reported
            3 when a finding at or above --fail-on was reported
            2 for a usage error, when no backend could be selected, or when no
              repositories were found
            1 when a scan failed, or on a backend, database, or write failure
        """
        path = os.path.abspath(self.path)
        if not os.path.isdir(path):
            logger.error("not a directory: %s", self.path)
            return 2
        if self.recursive:
            return self.scan_tree(path)
        return self.scan_repository(path)

    def scan_repository(self, path: str) -> int:
        """Scan the repository at `path` and write the report."""
        names = self.scans
        # Fail fast before the scan if the report file already exists. emit refuses to
        # overwrite as well, so a file appearing mid-scan is caught.
        if self.output is not None and Path(self.output).exists():
            logger.error(
                "output file already exists, refusing to overwrite: %s", self.output
            )
            return 2

        ignore_path = self.ignore_file
        if not self.no_ignore_file and ignore_path is None:
            default = os.path.join(path, ignore.DEFAULT_IGNORE_FILE)
            ignore_path = default if os.path.isfile(default) else None
        ignore_rules: list[ignore.IgnoreRule] = []
        if ignore_path is not None and not self.no_ignore_file:
            ignore_rules, errors = ignore.load(ignore_path)
            for msg in errors:
                logger.warning("%s", msg)

        user = get_host_user() if self.uid is None else RunUser(self.uid, self.uid, ())
        scans = [
            SCANS[name](
                **{
                    param.name: getattr(self, param.name)
                    for param in collect_params(SCANS[name])
                }
            )
            for name in names
        ]
        with start_session(
            self.backend,
            mount_source=path,
            image=self.image,
            user=user,
            env=resolve_env(self.env),
        ) as session:
            if not session.ok:
                return session.exit_code
            assert session.target is not None  # a source was given, so target is set

            analysis = run_analysis(
                session, scans, ignore_rules=ignore_rules, stream=True
            )
            report = sarif.SarifDocument.from_runs(analysis.sarif_runs)

            if self.db is not None:
                if is_err(err := db_write.write_analysis(self.db, analysis)):
                    logger.error(err.msg)
                    return 1
                logger.info("recorded analysis %s in %s", analysis.uuid, self.db)
            if self.output is not None or self.format == Format.JSON:
                if is_err(err := output.write_json(report.to_dict(), self.output)):
                    logger.error(err.msg)
                    return 1
            else:
                output.write_table(*report.to_table(), limit=self.limit, wrap=self.wrap)
            logger.info("scan complete: %d finding(s)", report.count())
            if analysis.failed_scans:
                return 1
            fails = _has_failing_finding(report.results, self.fail_on)
            return FINDINGS_EXIT_CODE if fails else 0

    def scan_tree(self, path: str) -> int:
        """Find and scan every repository in `path`."""
        for option_name, given in (
            ("-o", self.output is not None),
            ("-f", self.format is not None),
            ("-n", self.limit != DEFAULT_ROW_LIMIT),
            ("--wrap", self.wrap != DEFAULT_WRAP_LINES),
            ("--ignore-file", self.ignore_file is not None),
        ):
            if given:
                logger.error("%s can't be used with -r", option_name)
                return 2
        if self.db is None:
            logger.error("-r requires --db")
            return 2

        repositories = bulk.find_repositories(path)
        if not repositories:
            logger.error("no repositories under %s", self.path)
            return 2
        logger.info("scanning %d repositories", len(repositories))

        user = get_host_user() if self.uid is None else RunUser(self.uid, self.uid, ())
        results = bulk.scan_repositories(
            repositories,
            self.scans,
            db=self.db,
            backend=self.backend,
            image=self.image,
            user=user,
            env=resolve_env(self.env),
            threads=self.threads,
            options={
                param.name: getattr(self, param.name) for param in self.extra_options
            },
            use_ignore_files=not self.no_ignore_file,
        )
        analyses = [r for r in results.values() if isinstance(r, Analysis)]
        complete = [a for a in analyses if not a.failed_scans]
        findings: list[sarif.SarifResult] = []
        for analysis in analyses:
            for run in analysis.sarif_runs:
                findings.extend(run.results)
        logger.info(
            "scanned %d of %d repositories; %d finding(s) recorded in %s",
            len(complete),
            len(results),
            len(findings),
            self.db,
        )
        if len(complete) != len(results):
            return 1
        fails = _has_failing_finding(findings, self.fail_on)
        return FINDINGS_EXIT_CODE if fails else 0


def _has_failing_finding(findings: Iterable[sarif.SarifResult], fail_on: str) -> bool:
    """Check whether any of `findings` is at or above the `fail_on` level."""
    threshold = _FAIL_RANK.get(fail_on, 0)
    return bool(threshold) and any(
        _FAIL_RANK.get(finding.level, 2) >= threshold for finding in findings
    )
