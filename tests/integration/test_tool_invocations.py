# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests: build the real tool image and invoke every tool in it.

For each container backend (docker, lxd), force a real, hash-verified build of the tool
image, then run every tool through the real, unpatched `exec` with a
version probe, checking the pinned version appears in its output. This exercises the
whole path end to end: image creation and every tool invocation.

Excluded from the default unit run; invoke explicitly:

    tox run -f integration      (across the py310/py312/py314 matrix)
    OR
    tox run -e integration-py310
    OR
    pytest tests/integration -s --log-cli-level=INFO

Pass `--short` (e.g. `tox run -f integration -- --short`) to reuse an existing
tool image when it still verifies instead of forcing a rebuild, which skips the
slow LXD image build on re-runs.

Skipped when a backend is unavailable. Slow: the image build downloads and installs
every tool, so the first run per backend can take several minutes. The build output
streams live to the console (-s keeps pytest from capturing it) and each tool
invocation is logged at INFO (--log-cli-level=INFO), so the run narrates itself
instead of sitting silent; the tox integration envs set both.
"""

import io
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import (
    contextmanager,
    nullcontext,
    redirect_stderr,
    redirect_stdout,
)

import pytest

from reposcan.actions.exec import execute
from reposcan.backends import ContainerBackend, DockerBackend, LxdBackend
from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import Failure
from reposcan.image.build_spec import build_spec
from reposcan.image.builder import ensure_image
from reposcan.tools.install import current_platform
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


@contextmanager
def _isolated_cache() -> Iterator[None]:
    """Keep the image-identity cache out of the developer's ~/.local/share."""
    saved = os.environ.get("XDG_DATA_HOME")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["XDG_DATA_HOME"] = tmp
        try:
            yield
        finally:
            if saved is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = saved


def _invoke(ctx: ExecutionContext, name: str, args: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = execute(ctx, [name, *args], timeout=180)
    return code, out.getvalue() + err.getvalue()


def _probe_every_tool_in(
    backend: ContainerBackend, *, force_rebuild: bool = False
) -> None:
    availability = backend.availability()
    if not availability.ok:
        logger.warning(availability.reason)
        pytest.skip(f"{backend.name} unavailable: {availability.reason}")
    assert set(_VERSION_PROBE) == set(TOOLS)  # probe table matches the tool set

    builder = backend.image_builder()
    with _isolated_cache() if force_rebuild else nullcontext():
        action = "reusing" if force_rebuild else "building"
        logger.info("[%s] %s tool image; output follows", backend.name, action)
        reference = ensure_image(
            builder, build_spec(current_platform()), force=force_rebuild
        )
        assert not isinstance(reference, Failure), reference
        logger.info("[%s] starting container from %s", backend.name, reference)
        ctx = backend.context(reference)
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


def test_every_tool_runs_in_the_docker_image(request: pytest.FixtureRequest) -> None:
    short = bool(request.config.getoption("--short"))
    _probe_every_tool_in(DockerBackend(), force_rebuild=not short)


def test_every_tool_runs_in_the_lxd_image(request: pytest.FixtureRequest) -> None:
    short = bool(request.config.getoption("--short"))
    _probe_every_tool_in(LxdBackend(), force_rebuild=not short)
