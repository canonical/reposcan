# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan sbom` command."""

import logging
import os
from pathlib import Path

from repo_scanner import output
from repo_scanner.actions.base import Action
from repo_scanner.backends import start_session
from repo_scanner.cli_kit import flag, option, positional
from repo_scanner.db import write as db_write
from repo_scanner.execution.context import RunUser, host_user
from repo_scanner.execution.process import Failure
from repo_scanner.output import DEFAULT_ROW_LIMIT, Format
from repo_scanner.scans.analysis import Analysis, utc_now
from repo_scanner.scans.repo import read_repository_state
from repo_scanner.scans.run import run_sbom_scan
from repo_scanner.scans.sbom import SbomScan
from repo_scanner.table import DEFAULT_WRAP_LINES

logger = logging.getLogger(__name__)

FORMATS = tuple(f.value for f in Format)


class SbomCommand(Action):
    """Build a software bill of materials for a repository."""

    name = "sbom"
    help = "Build a software bill of materials (trivy, syft, cdxgen)."

    path: str = positional(help="Path to the repository to inventory.")
    output: str | None = option("-o", help="Write the SBOM to FILE instead of stdout.")
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
    include_dev_dependencies: bool = flag(
        help="Resolve development dependencies too (production-only default)."
    )
    allow_code_execution: bool = flag(
        help="Let dependency resolution build source packages, which runs untrusted "
        "repository code (off by default)."
    )

    def run(self) -> int:
        """Build the SBOM and write it.

        Exit codes:
            0 on success (an inventory is not pass/fail)
            2 for a usage error
            1 on a tool error or a write failure
        """
        path = os.path.abspath(self.path)
        if not os.path.isdir(path):
            logger.error("not a directory: %s", self.path)
            return 2
        if self.output is not None and Path(self.output).exists():
            logger.error(
                "output file already exists, refusing to overwrite: %s", self.output
            )
            return 2
        fmt = Format(self.format) if self.format else None

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

            analysis = Analysis.begin(
                read_repository_state(session.context, session.target)
            )
            started_at = utc_now()

            scan = SbomScan(
                include_dev_dependencies=self.include_dev_dependencies,
                allow_code_execution=self.allow_code_execution,
            )
            artifact = run_sbom_scan(
                scan,
                session.context,
                session.target,
                session.tool_root,
                resolved_parent=session.resolved_parent,
                stream=True,
            )
            if isinstance(artifact, Failure):
                logger.error("sbom failed: %s", artifact.reason)
                return 1

            analysis.add(scan.name, artifact, started_at=started_at)
            analysis.close()
            if self.db is not None:
                failed = db_write.analysis(self.db, analysis)
                if failed is not None:
                    logger.error(failed.reason)
                    return 1
                logger.info("recorded analysis %s in %s", analysis.uuid, self.db)

            failure = output.emit(
                artifact,
                output=self.output,
                fmt=fmt,
                limit=self.limit,
                wrap=self.wrap,
            )
            if isinstance(failure, Failure):
                logger.error(failure.reason)
                return 1
            logger.info("sbom complete: %d component(s)", artifact.count())
            return 0
