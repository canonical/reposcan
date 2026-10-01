# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test: a finding in a file that is not UTF-8 keeps its line hash.

trufflehog finds a secret inside a gzipped file by decompressing it, but reposcan
hashes the finding's line by reading the raw file back, which is not UTF-8.
"""

import gzip
import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from reposcan.backends import BACKENDS, start_session
from reposcan.execution.context import get_host_user
from reposcan.result import Err
from reposcan.scans.run import run_scan
from reposcan.scans.secrets import SecretsScan

logger = logging.getLogger(__name__)

# A well-formed but fake AWS key pair. Not the AWS "EXAMPLE" keys, which trufflehog
# filters as known placeholders.
_SECRET = (
    b"AWS_ACCESS_KEY_ID=AKIAZ7Q3N5W2PLKX4RTV\n"
    b"AWS_SECRET_ACCESS_KEY=Qm8xR2vT9pL4sN7wK3jH6fD1cB5zX0yA2eG8uI4o\n"
)


def test_secret_in_a_gzip_file_gets_a_line_hash() -> None:
    available = BACKENDS["docker"].check_availability()
    assert not isinstance(available, Err), "Docker is not available"

    with tempfile.TemporaryDirectory() as repo:
        Path(repo, "config.env.gz").write_bytes(gzip.compress(_SECRET, mtime=0))
        git = ["git", "-C", repo, "-c", "user.email=f@example.com", "-c", "user.name=f"]
        subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-qm", "x"], check=True)

        logger.info("scanning a repo with a gzipped secret")
        with start_session(
            "docker", mount_source=repo, user=get_host_user(), image="build"
        ) as session:
            assert session.ok, f"session failed (exit {session.exit_code})"
            assert session.target is not None
            run = run_scan(
                SecretsScan(), session.context, session.target, session.install_dir
            )

    assert not isinstance(run, Err), run.msg
    gzipped = [r for r in run.results if r.uri.endswith("config.env.gz")]
    assert gzipped, f"no finding in config.env.gz: {[r.uri for r in run.results]}"
    fingerprints = gzipped[0].result.get("partialFingerprints", {})
    assert fingerprints.get("primaryLocationLineHash"), (
        f"finding has no primaryLocationLineHash: {gzipped[0].result}"
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    test_secret_in_a_gzip_file_gets_a_line_hash()
    logger.info("passed")
