# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build a Docker image from a BuildSpec, via the docker CLI.

The image is a stock base plus the spec's install script run once at build time,
tagged by the spec digest. See image/ensure.py for the shared ensure step.
"""

import tempfile
from pathlib import Path

from reposcan.execution.process import run_process
from reposcan.image.spec import NAME, BuildSpec
from reposcan.result import Result, get_err, get_value, is_err


def read_image_identity(reference: str) -> str | None:
    """Read the Docker image ID (content hash) of `reference`."""
    argv = ["docker", "image", "inspect", "--format", "{{.Id}}", reference]
    run = get_value(run_process(argv, timeout=30, check=True))
    return run.stdout.strip() if run else None


def pull(ref: str) -> Result[None]:
    """Docker-pull `ref`."""
    argv = ["docker", "pull", ref]
    return get_err(
        run_process(argv, check=True, stream_stdout=True, stream_stderr=True)
    )


class DockerImageBuilder:
    """Builds Docker images (an ImageBuilder). Tags them `reposcan:<digest>`."""

    name = "docker"

    def derive_reference(self, spec: BuildSpec) -> str:
        return f"{NAME}:{spec.short_digest}"

    def read_identity(self, reference: str) -> str | None:
        return read_image_identity(reference)

    def build(self, spec: BuildSpec) -> Result[str]:
        # Build context: a temp dir with the install script and a Dockerfile that
        # runs it, then puts the tools' bin dir on PATH.
        tag = self.derive_reference(spec)
        dockerfile = (
            f"FROM {spec.base_image}\n"
            "COPY install.sh /tmp/install.sh\n"
            "RUN sh /tmp/install.sh && rm -f /tmp/install.sh\n"
            f'ENV PATH="{spec.install_dir}/bin:$PATH"\n'
        )
        with tempfile.TemporaryDirectory() as context:
            Path(context, "install.sh").write_text(spec.script)
            Path(context, "Dockerfile").write_text(dockerfile)
            build = ["docker", "build", "-t", tag, context]
            result = run_process(
                build, check=True, stream_stdout=True, stream_stderr=True
            )
        return result if is_err(result) else tag
