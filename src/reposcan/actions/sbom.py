# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan sbom` command."""

import logging
import os
from pathlib import Path

from reposcan import output
from reposcan.actions.base import Action
from reposcan.backends import start_session
from reposcan.cli_kit import flag, option, positional
from reposcan.db import write as db_write
from reposcan.execution.context import RunUser, host_user, resolved_env
from reposcan.execution.process import Failure
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.scans.analysis import Analysis, ScanRecord, utc_now
from reposcan.scans.repo import read_repository_state
from reposcan.scans.run import run_sbom_scan
from reposcan.scans.sbom import SbomScan
from reposcan.table import DEFAULT_WRAP_LINES

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

        user = host_user() if self.uid is None else RunUser(self.uid, self.uid, ())
        with start_session(
            self.backend,
            mount_source=path,
            image=self.image,
            user=user,
            env=resolved_env(self.env),
        ) as session:
            if not session.ok:
                return session.exit_code
            assert session.target is not None  # a source was given, so target is set

            state = read_repository_state(session.context, session.target)
            with Analysis.begin(state) as analysis:
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

                analysis.add(
                    ScanRecord.from_artifact(scan.name, artifact, started_at=started_at)
                )
            if self.db is not None:
                failed = db_write.analysis(self.db, analysis)
                if failed is not None:
                    logger.error(failed.reason)
                    return 1
                logger.info("recorded analysis %s in %s", analysis.uuid, self.db)

            if self.output is not None or self.format == Format.JSON:
                failure = output.write_json(artifact.to_dict(), self.output)
                if isinstance(failure, Failure):
                    logger.error(failure.reason)
                    return 1
            else:
                output.write_table(*artifact.rows(), limit=self.limit, wrap=self.wrap)
            logger.info("sbom complete: %d component(s)", artifact.count())
            return 0
