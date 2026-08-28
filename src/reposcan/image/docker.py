# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build a Docker image from a BuildSpec, via the docker CLI.

The image is a stock base plus the spec's install script run once at build time,
tagged by the spec digest. See image/builder.py for the shared ensure step.
"""

import tempfile
from pathlib import Path

from reposcan.execution.process import Failure, run_process, succeeded
from reposcan.image.build_spec import NAME, BuildSpec


class DockerImageBuilder:
    """Builds Docker images (an ImageBuilder). Tags them `reposcan:<digest>`."""

    name = "docker"

    def reference(self, spec: BuildSpec) -> str:
        return f"{NAME}:{spec.short_digest}"

    def identity(self, reference: str) -> str | None:
        # The image ID (a sha256) is Docker's content hash of the image.
        argv = ["docker", "image", "inspect", "--format", "{{.Id}}", reference]
        result = run_process(argv, timeout=30)
        if succeeded(result):
            return result.stdout.strip() or None
        return None

    def build(self, spec: BuildSpec) -> str | Failure:
        # Build context: a temp dir with the install script and a Dockerfile that
        # runs it, then puts the tools' bin dir on PATH.
        tag = self.reference(spec)
        dockerfile = (
            f"FROM {spec.base_image}\n"
            "COPY install.sh /tmp/install.sh\n"
            "RUN sh /tmp/install.sh && rm -f /tmp/install.sh\n"
            f'ENV PATH="{spec.install_root}/bin:$PATH"\n'
        )
        with tempfile.TemporaryDirectory() as context:
            Path(context, "install.sh").write_text(spec.script)
            Path(context, "Dockerfile").write_text(dockerfile)
            build = ["docker", "build", "-t", tag, context]
            result = run_process(
                build, check=True, stream_stdout=True, stream_stderr=True
            )
        return result if isinstance(result, Failure) else tag
