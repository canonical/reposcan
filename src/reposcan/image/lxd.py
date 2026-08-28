# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build an LXD image from a BuildSpec, via the lxc CLI.

LXD has no build file, so the image is produced by launching a build container from
the base, pushing the spec's install script in, running it, then publishing the
stopped container as an image aliased by the spec digest. See image/builder.py for
the shared ensure step.
"""

import logging
import os
import tempfile

from reposcan.execution.firewall import lxd_bridge_hint
from reposcan.execution.lxd import LXC, ensure_project
from reposcan.execution.process import ExecResult, Failure, run_process, succeeded
from reposcan.image.build_spec import NAME, BuildSpec

logger = logging.getLogger(__name__)


class LxdImageBuilder:
    """Builds LXD images (an ImageBuilder).

    Aliases them `reposcan-<digest>` -- an LXD alias cannot use a colon, which
    separates a remote from an image.
    """

    name = "lxd"

    def reference(self, spec: BuildSpec) -> str:
        return f"{NAME}-{spec.short_digest}"

    def identity(self, reference: str) -> str | None:
        # The image fingerprint (a sha256) is LXD's content hash of the image.
        result = run_process([*LXC, "image", "info", reference], timeout=30)
        if not (isinstance(result, ExecResult) and result.exit_code == 0):
            return None
        for line in result.stdout.splitlines():
            if line.strip().startswith("Fingerprint:"):
                return line.split(":", 1)[1].strip() or None
        return None

    def build(self, spec: BuildSpec) -> str | Failure:
        project_error = ensure_project()
        if project_error is not None:
            return project_error
        # A build container is always deleted afterwards, success or not.
        alias = self.reference(spec)
        # Remove any preexisting container with the same alias
        run_process([*LXC, "image", "delete", alias])
        handle = f"{NAME}-build-{os.getpid()}"
        launched = run_process(
            [*LXC, "launch", spec.base_image, handle],
            check=True,
            stream_stdout=True,
            stream_stderr=True,
        )
        if isinstance(launched, Failure):
            return launched
        error = self._provision(handle, spec, alias)
        run_process([*LXC, "delete", handle, "--force"])  # remove the builder
        return error if error is not None else alias

    def _provision(self, handle: str, spec: BuildSpec, alias: str) -> Failure | None:
        """Install the tools into the build container and publish it under `alias`.

        Waits for the container's network and aborts early if it has none, then
        installs the tools, stops the container, and publishes it. Returns None or the
        first Failure.
        """
        ready = run_process(
            [*LXC, "exec", handle, "--", "cloud-init", "status", "--wait"],
            check=True,
            stream_stdout=True,
            stream_stderr=True,
        )
        if isinstance(ready, Failure):
            return ready
        offline = _offline_reason(handle)
        if offline is not None:
            logger.error(offline.reason)
            return offline
        with tempfile.NamedTemporaryFile("w", suffix=".sh") as script:
            script.write(spec.script)
            script.flush()
            steps = [
                [*LXC, "file", "push", script.name, f"{handle}/root/install.sh"],
                [*LXC, "exec", handle, "--", "sh", "/root/install.sh"],
                [*LXC, "stop", handle],
                [*LXC, "publish", handle, "--alias", alias],
            ]
            for argv in steps:
                result = run_process(
                    argv, check=True, stream_stdout=True, stream_stderr=True
                )
                if isinstance(result, Failure):
                    return result
        return None


def _offline_reason(handle: str) -> Failure | None:
    """A Failure if the build container cannot reach the internet, else None.

    Probes by opening a TCP connection to github.com:443 from inside the container via
    bash's /dev/tcp (bash is always present in the base image, unlike curl or wget);
    `timeout` bounds a blocked bridge that would otherwise hang. The install needs
    github, PyPI, and the apt mirrors, so no outbound network is fatal and worth
    catching in seconds instead of a multi-minute download hang. On failure it logs a
    firewall/bridge hint (a blocked lxdbr0 bridge is the usual cause) before returning
    the Failure.
    """
    probe = run_process(
        [
            *LXC,
            "exec",
            handle,
            "--",
            "timeout",
            "15",
            "bash",
            "-c",
            "exec 3<>/dev/tcp/github.com/443",
        ]
    )
    if succeeded(probe):
        return None
    # Confirmed offline: surface the likely firewall cause and its fix as a warning
    # (this is the diagnostic that would otherwise never appear), then abort.
    logger.warning(lxd_bridge_hint())
    return Failure(
        reason="build container has no outbound network access; the tool install must "
        "reach github.com, PyPI, and the apt mirrors. Check the container's network, "
        "DNS, and NAT."
    )
