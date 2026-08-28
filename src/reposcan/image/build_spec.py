# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The image build spec: the build script and the image's content-addressed identity.

The same script installs the tools whichever way an image is built -- baked into a
Docker image with a RUN, or provisioned into an LXD image by pushing and exec'ing it
-- so there is one definition of what an image contains. It is the same per-tool
`install_commands` that `bootstrap` runs on the host, aggregated. See image/docker.py
and image/lxd.py.
"""

import hashlib
from dataclasses import dataclass

from reposcan.execution.context import (
    MOUNT_PARENT,
    RESOLVED_PARENT,
    SCAN_GID,
    SCAN_UID,
    SCAN_USER,
)
from reposcan.tools.install import install_plan
from reposcan.tools.model import Platform
from reposcan.tools.registry import RESOLVER_TOOLS, TOOLS, UV_PYTHON_SUBDIR

# The image name that built images are tagged/aliased under (with the spec digest).
NAME = "reposcan"

# The base image and in-image install location. Both feed the spec digest, so a
# change to either yields a new image identity.
BASE_IMAGE = "ubuntu:26.04"
INSTALL_ROOT = "/opt/reposcan"

# Packages needed at build or scan time that may not be in the base image:
_BASE_PACKAGES = (
    "curl",  # for downloads
    "ca-certificates",  # for downloads
    "git",  # for tools that scan git history (trufflehog)
)


def build_script(platform: Platform, install_root: str = INSTALL_ROOT) -> str:
    """The shell script that installs every tool into `install_root`, for `platform`.

    It runs under `set -eu`, so any failure aborts the build: a half-built image is
    worse than none. Each tool's own install commands are reused verbatim.

    Args:
        platform: The OS/arch the install commands target.
        install_root: The in-image directory the tools install under.

    Returns:
        The complete `set -eu` shell script that installs every tool.
    """
    lines = [
        "#!/bin/sh",
        "set -eu",
        "export DEBIAN_FRONTEND=noninteractive",
        # PyPI tools install into uv venvs whose interpreter is uv's managed Python.
        # By default uv puts that under root's home (mode 0700), which the unprivileged
        # scan user cannot read, so its stdlib import fails ("No module named
        # 'encodings'"). Keep it under install_root, which the chmod below opens up.
        f'export UV_PYTHON_INSTALL_DIR="{install_root}/{UV_PYTHON_SUBDIR}"',
        "apt-get update",
        f"apt-get install -y --no-install-recommends {' '.join(_BASE_PACKAGES)}",
        "rm -rf /var/lib/apt/lists/*",
        # fix git's "detected dubious ownership" error; recursive match needs git >=2.46
        f"git config --system --add safe.directory '{MOUNT_PARENT}/*'",
        # dependency resolution copies the repo here; git ls-files (exclusion) runs on
        # the copy, so trust it too.
        f"git config --system --add safe.directory '{RESOLVED_PARENT}/*'",
        # create an unprivileged user for later use
        f"groupadd --gid {SCAN_GID} {SCAN_USER}",
        f"useradd --create-home --uid {SCAN_UID} --gid {SCAN_GID} "
        # --shell nologin since it is only ever setpriv'd into.
        f"--shell /usr/sbin/nologin {SCAN_USER}",
        # the resolution copy dir, world-writable (sticky, like /tmp) so the
        # invoking host user can write the repo copy there -- it is not known at
        # build time, and the container is ephemeral and single-tenant.
        f"mkdir -p {RESOLVED_PARENT}",
        f"chmod 1777 {RESOLVED_PARENT}",
    ]
    for step in install_plan(
        [*TOOLS.values(), *RESOLVER_TOOLS], platform, install_root
    ):
        lines.append(f"# {step.tool.name} {step.tool.version}")
        lines.extend(step.commands)
    # tools are installed as root; make them readable and executable by the scan user.
    lines.append(f"chmod -R a+rX {install_root}")
    # Symlink every tool binary onto /usr/local/bin (on PATH for docker/lxd `exec`
    lines.append(
        f'for f in {install_root}/bin/*; do ln -sf "$f" '
        f'"/usr/local/bin/$(basename "$f")"; done'
    )
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class BuildSpec:
    """A build script plus the inputs that define the built image's identity.

    The `digest` content-addresses the image: an unchanged spec reuses the built image,
    and any change (a tool version or hash, the base image, the install root) produces
    a new digest and so a new image.
    """

    base_image: str
    install_root: str
    script: str

    @property
    def digest(self) -> str:
        material = "\n".join([self.base_image, self.install_root, self.script])
        return hashlib.sha256(material.encode()).hexdigest()

    @property
    def short_digest(self) -> str:
        return self.digest[:12]


def build_spec(
    platform: Platform,
    base_image: str = BASE_IMAGE,
    install_root: str = INSTALL_ROOT,
) -> BuildSpec:
    """The build spec for an image containing every tool, built for `platform`.

    Args:
        platform: The OS/arch the image is built for.
        base_image: The base image the build starts from.
        install_root: The in-image directory the tools install under.

    Returns:
        The BuildSpec whose digest content-addresses the resulting image.
    """
    return BuildSpec(base_image, install_root, build_script(platform, install_root))
