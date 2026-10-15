# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""`reposcan db` commands."""

import logging
import os

from reposcan.actions.base import Action
from reposcan.cli_kit import Group, flag, option, positional
from reposcan.db import write as db_write
from reposcan.result import Err

logger = logging.getLogger(__name__)


class DbImport(Action):
    name = "import"
    help = "Import every analysis of another reposcan database."

    source: str = positional(help="The database to import. It is never modified.")
    db: str = option(
        required=True,
        help="Record the imported analyses in the database at FILE, creating it if "
        "absent.",
    )
    produced_by: str = option(
        required=True,
        help="Who produced the analyses SOURCE ran itself, such as the machine or "
        "CI job; recorded with each of them.",
    )
    retain_secrets: bool = flag(
        help="Keep the raw secret values that SOURCE's findings retained. Off by "
        "default: they are dropped, keeping live credentials out of --db.",
    )

    def run(self) -> int:
        """Import SOURCE's analyses into --db.

        Exit codes:
            0 when every analysis was imported or was already there
            1 when a database is unusable or an analysis fails to import
            2 when --produced-by is blank, or SOURCE is not a file or is the --db file
        """
        if not self.produced_by.strip():
            logger.error("--produced-by must name who produced the analyses")
            return 2
        if not os.path.isfile(self.source):
            logger.error("not a file: %s", self.source)
            return 2
        if os.path.exists(self.db) and os.path.samefile(self.source, self.db):
            logger.error("refusing to import %s into itself", self.source)
            return 2
        result = db_write.import_database(
            self.source, self.db, self.produced_by, retain_secrets=self.retain_secrets
        )
        if isinstance(result, Err):
            logger.error("%s", result.msg)
            return 1
        logger.info(
            "imported %d analyses from %s into %s; %d were already there",
            result.imported,
            self.source,
            self.db,
            result.skipped,
        )
        return 0


class DbGroup(Group):
    name = "db"
    help = "Work with a reposcan database."
    subcommands = (DbImport,)
