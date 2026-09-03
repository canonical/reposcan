# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The ImageBuilder Protocol and the backend-agnostic ensure step.

An ImageBuilder turns a BuildSpec into a built image for one backend (Docker or LXD).
The backends differ only in how they name, hash, and build an image; the
build-on-demand-and-verify logic is the same for both and lives here, in
`ensure_built`.

`ensure_built` is the trust boundary: an image is reused only when the one present
matches the identity we recorded when we built it (see image/cache.py). A missing
image, or one whose hash does not match what we recorded, is (re)built and its new
identity captured. So a tampered-with or unknown image is never run.
"""

import logging
from typing import Protocol

from reposcan.execution.process import Failure
from reposcan.image import cache
from reposcan.image.build_spec import BuildSpec

logger = logging.getLogger(__name__)


class ImageBuilder(Protocol):
    """Builds images for one backend. `name` labels it ("docker" | "lxd")."""

    name: str

    def reference(self, spec: BuildSpec) -> str:
        """Deterministically generate a tag or alias for the `spec`-based image."""
        ...

    def identity(self, reference: str) -> str | None:
        """Read the content hash of the image `reference`.

        The hash is the Docker image ID or LXD fingerprint; None means no such image
        is currently present.
        """
        ...

    def build(self, spec: BuildSpec) -> str | Failure:
        """Build the image unconditionally, returning its reference or a Failure."""
        ...


def ensure_built(
    builder: ImageBuilder, spec: BuildSpec, *, force: bool = False
) -> str | Failure:
    """Build a verified image from `spec` and return its reference.

    Reuses the present image only when its hash matches the identity recorded at its
    last build; otherwise (missing, mismatched, or `force`) it is rebuilt and its
    identity re-recorded.

    Args:
        builder: The backend builder that names, hashes, and builds the image.
        spec: The build spec that content-addresses the image.
        force: Rebuild even when a matching image is already present.

    Returns:
        The verified image reference, or a Failure if the build failed or the image
        vanished after building.
    """
    reference = builder.reference(spec)
    if not force:
        present = builder.identity(reference)
        if present is not None and present == cache.recorded(reference):
            logger.info("%s image %s verified; reusing", builder.name, reference)
            return reference
        if present is not None:
            logger.info(
                "%s image %s does not match its recorded identity; rebuilding",
                builder.name,
                reference,
            )
    logger.info("building %s image %s ...", builder.name, reference)
    result = builder.build(spec)
    if isinstance(result, Failure):
        return result
    identity = builder.identity(reference)
    if identity is None:
        return Failure(reason=f"{builder.name} image {reference} vanished after build")
    cache.record(reference, identity)
    return reference
