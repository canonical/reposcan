# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests using the docker execution context."""

import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from reposcan.backends import BACKENDS
from reposcan.execution.context import Mount, locate_mounted_target
from reposcan.execution.docker import DockerContext
from reposcan.image.spec import BASE_IMAGE
from reposcan.result import Err
from tests.integration.shared import exercise_lifecycle

logger = logging.getLogger(__name__)

# A formattted but fake AWS key pair. trufflehog filters known placeholders.
_SECRET = (
    "AWS_ACCESS_KEY_ID=AKIAZ7Q3N5W2PLKX4RTV\n"
    "AWS_SECRET_ACCESS_KEY=Qm8xR2vT9pL4sN7wK3jH6fD1cB5zX0yA2eG8uI4o\n"
)


def test_docker_context_lifecycle() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not isinstance(available, Err), f"docker unavailable: {available.msg}"

    logger.info("[docker] starting ubuntu:26.04 container")
    ctx = DockerContext(BASE_IMAGE)
    started = ctx.start()
    assert started is None, f"docker run failed: {started}"
    try:
        exercise_lifecycle(ctx)
    finally:
        ctx.stop()

    # After stop the context has no running container.
    assert isinstance(ctx.run(["true"]), Err)


def test_docker_context_mounts_a_source_read_only() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not isinstance(available, Err), f"docker unavailable: {available.msg}"

    with tempfile.TemporaryDirectory() as source:
        Path(source, "marker.txt").write_text("hello")
        target = locate_mounted_target(source)
        logger.info("[docker] mounting %s at %s", source, target)
        ctx = DockerContext(BASE_IMAGE, mounts=[Mount(source, target)])
        assert not isinstance(ctx.start(), Err)
        try:
            # The mounted file is visible inside the container at the kept-name path.
            seen = ctx.run(["cat", f"{target}/marker.txt"])
            assert not isinstance(seen, Err) and seen.exit_code == 0, seen
            assert seen.stdout.strip() == "hello"
            # The mount is read-only: writing into it fails.
            write = ctx.run(["sh", "-c", f"echo x > {target}/new.txt"])
            assert not isinstance(write, Err) and write.exit_code != 0, write
        finally:
            ctx.stop()


def test_docker_scan_of_a_worktree_finds_its_history_without_leaking_paths() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not isinstance(available, Err), f"docker unavailable: {available.msg}"

    with tempfile.TemporaryDirectory() as directory:
        # A repo under a stand-in home dir: commit a secret, then delete it.
        home = Path(directory, "home", "someone")
        repo = home / "acme-api"
        repo.mkdir(parents=True)
        git = ["git", "-C", str(repo), "-c", "user.name=f", "-c", "user.email=f@x.com"]
        (repo / "config.env").write_text(_SECRET)
        subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-qm", "add config"], check=True)
        subprocess.run([*git, "rm", "-q", "config.env"], check=True)
        subprocess.run([*git, "commit", "-qm", "remove config"], check=True)
        # A worktree, whose .git is only a pointer back into the repo.
        worktree = home / "worktrees" / "acme-api"
        subprocess.run([*git, "worktree", "add", "-q", "--detach", str(worktree)])

        report = Path(directory, "report.sarif")
        reposcan = [sys.executable, "-m", "reposcan", "--backend", "docker"]
        subprocess.run(
            [*reposcan, "--image", "build", "scan", "secrets", str(worktree)]
            + ["-o", str(report)]
        )
        text = report.read_text()

    # The secret is only in git history, so finding it means history was visible.
    assert '"AWS"' in text and "config.env" in text, text
    # The host path the repo lives under never reaches the report.
    assert str(home) not in text
