# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scan base classes: shared CLI options and the run/emit flow scans inherit.

A concrete scan subclasses `ScanAction` (or `DependencyResolvingScan`), sets its
name/help, declares any scan-specific options, and implements `invocations` and
`consolidate`. `ScanAction.run` handles the CLI-and-backend concerns -- validating the
path, starting the session, resolving dependencies (when needed), running the tools
via `run_scan`, emitting the report, and choosing the exit code.
"""

import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from repo_scanner.actions.base import Action
from repo_scanner.backends import start_session
from repo_scanner.cli_kit import flag, option, positional
from repo_scanner.execution.context import RunUser, host_user
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.ioutil.table import DEFAULT_WRAP_LINES
from repo_scanner.scans import cyclonedx, ignore, output, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocation
from repo_scanner.scans.output import DEFAULT_ROW_LIMIT, Format
from repo_scanner.scans.run import run_scan

logger = logging.getLogger(__name__)

FORMATS = tuple(f.value for f in Format)

# Exit code when a scan completes and reports one or more findings.
FINDINGS_EXIT_CODE = 3


class ScanAction(Action):
    """Base for every scan: shared target/report options and the run/emit flow.

    A concrete scan subclasses this, sets `name`/`help`, declares any scan-specific
    options, and implements `invocations`/`parse`.
    """

    resolves_dependencies: ClassVar[bool] = False
    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.SARIF

    path: str = positional(help="Path to the repository to scan.")
    output: str | None = option(
        "-o", help="Write the report to FILE instead of stdout."
    )
    format: str | None = option("-f", choices=FORMATS, help="Output format.")
    limit: int = option(
        "-n",
        default=DEFAULT_ROW_LIMIT,
        convert=int,
        help="Maximum rows shown in the table.",
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

    def invocations(self, target: str) -> list[ToolInvocation]:
        """The tool invocations to run against `target`, in run order."""
        raise NotImplementedError

    def parse(self, tool: str, output: ExecResult, target: str) -> Artifact | Failure:
        """Parse and normalize a tool invocation's raw output into an Artifact.

        Called once per executed tool. `tool` is the scanner that produced `output`;
        `target` is the scan root, used to make finding uris repository-root-relative.
        """
        raise NotImplementedError

    def consolidate(self, artifacts: Sequence[Artifact]) -> Artifact | Failure:
        """Merge the per-tool Artifacts."""
        if self.artifact_kind is ArtifactKind.CYCLONEDX:
            return cyclonedx.merge(artifacts)
        return sarif.merge(artifacts)

    def run(self) -> int:
        """Run the scan end to end and return an exit code.

        For a findings scan (SARIF): 0 when it found nothing, 3 when it found
        something. For an inventory scan (SBOM/CycloneDX): 0. 2 for a bad path or when
        the output file already exists. 1 on a scan or tool error, or a write failure.
        """
        path = os.path.abspath(self.path)
        if not os.path.isdir(path):
            logger.error("not a directory: %s", self.path)
            return 2
        # Fail fast before the (slow) scan if the report file already exists. This is
        # only a courtesy check: emit refuses to overwrite atomically at write time, so
        # a file appearing during the scan is still caught (as a write Failure below).
        if self.output is not None and Path(self.output).exists():
            logger.error(
                "output file already exists, refusing to overwrite: %s", self.output
            )
            return 2
        fmt, error = output.choose_format(self.format, self.output)
        if error is not None:
            logger.warning("%s", error)
            return 2
        # Resolve the ignorefile: an explicit --ignore-file, else the default in the
        # repo when present, unless --no-ignore-file disables it. Malformed lines warn.
        ignore_path = self.ignore_file
        if not self.no_ignore_file and ignore_path is None:
            default = os.path.join(path, ignore.DEFAULT_IGNORE_FILE)
            ignore_path = default if os.path.isfile(default) else None
        ignore_rules: list[ignore.IgnoreRule] = []
        if ignore_path is not None and not self.no_ignore_file:
            ignore_rules, errors = ignore.load(ignore_path)
            for message in errors:
                logger.warning("%s", message)
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
            artifact = run_scan(
                self,
                session.context,
                session.target,
                session.tool_root,
                resolved_parent=session.resolved_parent,
                stream=True,
            )
            if isinstance(artifact, Failure):
                logger.error(artifact.reason)
                return 1

            removed = ignore.apply(artifact, ignore_rules)
            if removed:
                logger.info("ignored %d finding(s) via %s", removed, ignore_path)

            failure = output.emit(
                artifact, output=self.output, fmt=fmt, limit=self.limit, wrap=self.wrap
            )
            if isinstance(failure, Failure):
                logger.error(failure.reason)
                return 1

            if artifact.kind is ArtifactKind.CYCLONEDX:
                # An SBOM is an inventory, not pass/fail: report the size, exit 0.
                logger.info(
                    "%s scan complete: %d component(s)", self.name, artifact.count()
                )
                return 0
            count = artifact.count()
            logger.info("%s scan complete: %d finding(s)", self.name, count)
            return FINDINGS_EXIT_CODE if count else 0


class DependencyResolvingScan(ScanAction):
    """Base for scans that resolve the dependency tree before scanning (sbom, sca)."""

    resolves_dependencies: ClassVar[bool] = True

    include_dev_dependencies: bool = flag(
        help="Include development dependencies when resolving the dependency tree."
    )
    allow_code_execution: bool = flag(
        help="Let dependency resolution build source packages when needed "
        "(runs untrusted repository code). Off by default."
    )
