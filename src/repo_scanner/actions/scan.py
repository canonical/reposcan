# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan scan` command.

`reposcan scan <types> <path>` runs each requested scan type against a repository in
one backend session, then consolidates their findings into a single SARIF report.
`<types>` is one scan type or several, comma-separated -- or `all` for every type.

Each scan's options (secrets' `--mode`/`--depth`, sca's
`--include-dev-dependencies`/`--allow-code-execution`) are declared on the scan classes
and aggregated onto this command via `extra_options`; each carries a `requires` that its
scan be among the selected types, so an option for an unselected scan is a usage error.
"""

import copy
import logging
import os
from pathlib import Path

from repo_scanner.actions.base import Action
from repo_scanner.backends import start_session
from repo_scanner.cli_kit import Param, flag, option, params_of, positional
from repo_scanner.execution.context import RunUser, host_user
from repo_scanner.execution.process import Failure
from repo_scanner.ioutil.table import DEFAULT_WRAP_LINES
from repo_scanner.scans import ignore, output, sarif
from repo_scanner.scans.base import SecurityScan
from repo_scanner.scans.model import ArtifactKind
from repo_scanner.scans.output import DEFAULT_ROW_LIMIT, Format
from repo_scanner.scans.registry import SCANS
from repo_scanner.scans.run import run_scan

logger = logging.getLogger(__name__)

FORMATS = tuple(f.value for f in Format)

# Exit code when a scan completes and reports one or more findings.
FINDINGS_EXIT_CODE = 3


def _scan_names(raw: str) -> list[str]:
    """The scan-type names in comma-separated `raw`, validated and deduped in order.

    Used as the `scans` positional's converter, so an empty or unknown type is a usage
    error before anything runs. The meta-name `all` expands to every scan type.
    """
    names: list[str] = []
    for token in raw.split(","):
        name = token.strip()
        if not name:
            continue
        if name == "all":
            selected = list(SCANS)
        elif name in SCANS:
            selected = [name]
        else:
            valid = ", ".join([*SCANS, "all"])
            raise ValueError(f"unknown scan type {name!r} (choose from: {valid})")
        for chosen in selected:
            if chosen not in names:
                names.append(chosen)
    if not names:
        raise ValueError("give at least one scan type")
    return names


def _aggregate_scan_options(scans: dict[str, type[SecurityScan]]) -> tuple[Param, ...]:
    """The union of each scan's options, each requiring its scan(s) to be selected.

    A scan-specific option is only meaningful when a scan that declares it is selected,
    so each aggregated option gains a `requires` that the `scans` list contain one of
    its declaring scans.
    """
    declared_by: dict[str, list[str]] = {}
    params: dict[str, Param] = {}
    for scan_name, scan_class in scans.items():
        for param in params_of(scan_class):
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
        convert=_scan_names,
        help="Scan type(s), comma-separated: secrets, sast, iac, workflow, sca, "
        "or all (e.g. sast,secrets).",
    )
    path: str = positional(help="Path to the repository to scan.")
    output: str | None = option(
        "-o", help="Write the report to FILE instead of stdout."
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

    extra_options = _aggregate_scan_options(SCANS)

    def run(self) -> int:
        """Run the requested scans and return an exit code.

        Exit codes:
            0 when no scan reported anything
            3 when any scan reported something
            2 for a usage error
            1 on a scan/tool error or a write failure
        """
        names = self.scans
        path = os.path.abspath(self.path)
        if not os.path.isdir(path):
            logger.error("not a directory: %s", self.path)
            return 2
        # Fail fast before the scan if the report file already exists. emit refuses to
        # overwrite as well, so a file appearing mid-scan is caught.
        if self.output is not None and Path(self.output).exists():
            logger.error(
                "output file already exists, refusing to overwrite: %s", self.output
            )
            return 2
        fmt, error = output.choose_format(self.format, self.output)
        if error is not None:
            logger.warning("%s", error)
            return 2

        # throw an error upfront if selected output type is invalid (findings are SARIF)
        error = output.unwritable({ArtifactKind.SARIF}, fmt, self.output)
        if error is not None:
            logger.error("%s", error)
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

        user = host_user() if self.uid is None else RunUser(self.uid, self.uid, ())
        with start_session(
            self.backend,
            tool_image=True,
            mount_source=path,
            image=self.image,
            user=user,
        ) as session:
            if not session.ok:
                return session.exit_code
            assert session.target is not None  # a source was given, so target is set
            runs: list[sarif.SarifRun] = []
            for name in names:
                scan_cls = SCANS[name]
                scan = scan_cls(
                    **{
                        param.name: getattr(self, param.name)
                        for param in params_of(scan_cls)
                    }
                )
                run = run_scan(
                    scan,
                    session.context,
                    session.target,
                    session.tool_root,
                    resolved_parent=session.resolved_parent,
                    stream=True,
                )
                if isinstance(run, Failure):
                    logger.error("%s scan failed: %s", name, run.reason)
                    return 1
                runs.append(run)

            report = sarif.SarifDocument.from_runs(runs)
            removed = ignore.apply(report, ignore_rules, path)
            if removed:
                logger.info("ignored %d finding(s) via %s", removed, ignore_path)
            failure = output.emit_all(
                [report],
                output=self.output,
                fmt=fmt,
                limit=self.limit,
                wrap=self.wrap,
            )
            if isinstance(failure, Failure):
                logger.error(failure.reason)
                return 1
            count = report.count()
            logger.info("scan complete: %d finding(s)", report.count())
            return FINDINGS_EXIT_CODE if count else 0
