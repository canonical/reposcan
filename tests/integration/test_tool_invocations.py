# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests: build the real reposcan image and invoke every tool in it.

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
reposcan image when it still verifies instead of forcing a rebuild, which skips the
slow LXD image build on re-runs.

Skipped when a backend is unavailable. Slow: the image build downloads and installs
every tool, so the first run per backend can take several minutes. The build output
streams live to the console (-s keeps pytest from capturing it) and each tool
invocation is logged at INFO (--log-cli-level=INFO), so the run narrates itself
instead of sitting silent; the tox integration envs set both.
"""

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

import pytest

from reposcan import paths
from reposcan.actions.exec import execute
from reposcan.backends import BACKENDS, Backend
from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import Failure
from reposcan.image.ensure import ensure_built
from reposcan.image.spec import build_spec
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


def _probe_every_tool_in(backend: Backend, *, force_rebuild: bool = False) -> None:
    availability = backend.check_availability()
    if not availability.ok:
        logger.warning(availability.reason)
        pytest.skip(f"{backend.name} unavailable: {availability.reason}")
    assert set(_VERSION_PROBE) == set(TOOLS)  # probe table matches the tool set

    builder, open_context = backend.builder, backend.context
    assert builder is not None and open_context is not None  # a container backend
    with _isolated_cache() if force_rebuild else nullcontext():
        action = "reusing" if force_rebuild else "building"
        logger.info("[%s] %s reposcan image; output follows", backend.name, action)
        reference = ensure_built(
            builder, build_spec(detect_platform()), force=force_rebuild
        )
        assert not isinstance(reference, Failure), reference
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


def test_every_tool_runs_in_the_docker_image(request: pytest.FixtureRequest) -> None:
    short = bool(request.config.getoption("--short"))
    _probe_every_tool_in(BACKENDS["docker"], force_rebuild=not short)


def test_every_tool_runs_in_the_lxd_image(request: pytest.FixtureRequest) -> None:
    short = bool(request.config.getoption("--short"))
    _probe_every_tool_in(BACKENDS["lxd"], force_rebuild=not short)
