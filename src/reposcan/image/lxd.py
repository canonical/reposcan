# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build an LXD image from a BuildSpec, via the lxc CLI.

LXD has no build file, so the image is produced by launching a build container from
the base, pushing the spec's install script in, running it, then publishing the
stopped container as an image aliased by the spec digest. See image/ensure.py for
the shared ensure step.
"""

import logging
import os
import tempfile

from reposcan.execution.firewall import build_lxd_bridge_hint
from reposcan.execution.lxd import LXC, ensure_project
from reposcan.execution.process import run_process
from reposcan.image.spec import NAME, BuildSpec
from reposcan.result import Err, Result, get_value, is_err

logger = logging.getLogger(__name__)


class LxdImageBuilder:
    """Builds LXD images (an ImageBuilder).

    Aliases them `reposcan-<digest>` -- an LXD alias cannot use a colon, which
    separates a remote from an image.
    """

    name = "lxd"

    def derive_reference(self, spec: BuildSpec) -> str:
        return f"{NAME}-{spec.short_digest}"

    def read_identity(self, reference: str) -> str | None:
        # The image fingerprint (a sha256) is LXD's content hash of the image.
        run = get_value(run_process([*LXC, "image", "info", reference], timeout=30))
        if run is None:
            return None
        for line in run.stdout.splitlines():
            if line.strip().startswith("Fingerprint:"):
                return line.split(":", 1)[1].strip() or None
        return None

    def build(self, spec: BuildSpec) -> Result[str]:
        if is_err(err := ensure_project()):
            return err
        # A build container is always deleted afterwards, success or not.
        alias = self.derive_reference(spec)
        # Remove any preexisting container with the same alias
        run_process([*LXC, "image", "delete", alias])
        handle = f"{NAME}-build-{os.getpid()}"
        result = run_process(
            [*LXC, "launch", spec.base_image, handle],
            check=True,
            stream_stdout=True,
            stream_stderr=True,
        )
        if is_err(result):
            return result
        err = self._provision(handle, spec, alias)
        run_process([*LXC, "delete", handle, "--force"])  # remove the builder
        return err if is_err(err) else alias

    def _provision(self, handle: str, spec: BuildSpec, alias: str) -> Result[None]:
        """Install the tools into the build container and publish it under `alias`.

        Waits for the container's network and aborts early if it has none, then
        installs the tools, stops the container, and publishes it.
        """
        ready = run_process(
            [*LXC, "exec", handle, "--", "cloud-init", "status", "--wait"],
            check=True,
            stream_stdout=True,
            stream_stderr=True,
        )
        if is_err(ready):
            return ready
        if is_err(err := _verify_online(handle)):
            logger.error(err.msg)
            return err
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
                if is_err(result):
                    return result
        return None


def _verify_online(handle: str) -> Result[None]:
    """Verify the build container can reach the internet.

    Probes by opening a TCP connection to github.com:443 from inside the container via
    bash's /dev/tcp (bash is always present in the base image, unlike curl or wget);
    `timeout` bounds a blocked bridge that would otherwise hang. The install needs
    github, PyPI, and the apt mirrors, so no outbound network is fatal and worth
    catching in seconds instead of a multi-minute download hang. On failure it logs a
    firewall/bridge hint (a blocked lxdbr0 bridge is the usual cause) before returning
    the error.
    """
    test_result = run_process(
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
        ],
        check=True,
    )
    if not is_err(test_result):
        return None
    # Confirmed offline: surface the likely firewall cause and its fix as a warning
    # (this is the diagnostic that would otherwise never appear), then abort.
    logger.warning(build_lxd_bridge_hint())
    return Err(
        "build container has no outbound network access; the tool install "
        "must reach github.com, PyPI, and the apt mirrors. Check the container's "
        "network, DNS, and NAT."
    )
