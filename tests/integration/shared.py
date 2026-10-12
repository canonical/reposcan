# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared utils for the docker and lxd integration tests."""

import io
import logging
import pathlib
import tempfile
from collections.abc import Iterator
from contextlib import (
    contextmanager,
    nullcontext,
    redirect_stderr,
    redirect_stdout,
)

from reposcan import paths
from reposcan.actions.exec import execute
from reposcan.backends import Backend
from reposcan.execution.context import ExecutionContext
from reposcan.image.ensure import ensure_built
from reposcan.image.spec import build_spec
from reposcan.result import Err
from reposcan.tools.install import detect_platform
from reposcan.tools.registry import TOOLS

logger = logging.getLogger(__name__)


# The command that makes each tool print its version. The expected result is the tool's
# pinned version from the registry, so the fixture can't drift from what is installed.
_VERSION_PROBE = {
    "semgrep": ["--version"],
    "checkov": ["--version"],
    "zizmor": ["--version"],
    "trufflehog": ["--version"],
    "syft": ["--version"],
    "grype": ["--version"],
    "trivy": ["--version"],
    "poutine": ["version"],
    "cdxgen": ["--version"],
    "govulncheck": ["-version"],
}


def exercise_lifecycle(ctx: ExecutionContext) -> None:
    """Test execution context lifecycle.

    Run a series of commands in an already-started context and check that:
     - they execute inside an ubuntu:26.04 container
     - cwd, env, and exit-code are honored.
    """
    # Runs in the ubuntu:26.04 image, not on the host.
    os_release = ctx.run(["cat", "/etc/os-release"])
    assert not isinstance(os_release, Err)
    assert os_release.exit_code == 0
    assert 'VERSION_ID="26.04"' in os_release.stdout

    # The command's exit code is propagated.
    exit_code = ctx.run(["sh", "-c", "exit 7"])
    assert not isinstance(exit_code, Err)
    assert exit_code.exit_code == 7

    # Per-command env reaches the container.
    env = ctx.run(["sh", "-c", "echo $REPOSCAN_IT"], env={"REPOSCAN_IT": "present"})
    assert not isinstance(env, Err)
    assert env.stdout.strip() == "present"

    # cwd is honored.
    cwd = ctx.run(["pwd"], cwd="/tmp")
    assert not isinstance(cwd, Err)
    assert cwd.stdout.strip() == "/tmp"


@contextmanager
def _isolated_cache() -> Iterator[None]:
    """Keep the image-identity cache out of the developer's ~/.local/share."""
    saved = paths.IMAGE_CACHE
    with tempfile.TemporaryDirectory() as tmp:
        paths.IMAGE_CACHE = pathlib.Path(tmp) / "reposcan" / "images.json"
        try:
            yield
        finally:
            paths.IMAGE_CACHE = saved


def _invoke(ctx: ExecutionContext, name: str, args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = execute(ctx, [name, *args], timeout=180)
    return code, out.getvalue() + err.getvalue()


def probe_every_tool_in(backend: Backend, *, force_rebuild: bool = False) -> None:
    """Build the reposcan image in `backend` and invoke every tool in it.

    Force a real, hash-verified build of the reposcan image, then run every tool through
    the real, unpatched `exec` with a version probe, checking the pinned version appears
    in its output. This exercises the whole path end to end: image creation and tool
    usage.

    This test is slow: the image build downloads and installs every tool, so the first
    run can take several minutes. The build output streams live to the console and each
    tool invocation is logged at INFO, so the run's progress is visible.
    """
    available = backend.check_availability()
    assert not isinstance(available, Err), (
        f"{backend.name} unavailable: {available.msg}"
    )
    assert set(_VERSION_PROBE) == set(TOOLS)  # probe table matches the tool set

    builder, open_context = backend.builder, backend.context
    assert builder is not None and open_context is not None  # a container backend
    with _isolated_cache() if force_rebuild else nullcontext():
        action = "reusing" if force_rebuild else "building"
        logger.info("[%s] %s reposcan image; output follows", backend.name, action)
        reference = ensure_built(
            builder, build_spec(detect_platform()), force=force_rebuild
        )
        assert not isinstance(reference, Err)
        logger.info("[%s] starting container from %s", backend.name, reference)
        ctx = open_context(reference)
        started = ctx.start()
        assert started is None, f"{backend.name} container failed to start: {started}"
        try:
            for name, args in _VERSION_PROBE.items():
                logger.info("[%s] invoke %s %s", backend.name, name, " ".join(args))
                code, output = _invoke(ctx, name, args)
                assert code == 0, f"{name} exited {code}: {output}"
                assert TOOLS[name].version in output, f"{name}: {output!r}"
                logger.info("[%s] %s -> %s OK", backend.name, name, TOOLS[name].version)
        finally:
            ctx.stop()
