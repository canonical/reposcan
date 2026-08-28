# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan image` group: build the tool image and manage the image cache."""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.backends import ContainerBackend, select_backend
from reposcan.cli_kit import Group, flag, positional
from reposcan.execution.process import Failure
from reposcan.image import cache
from reposcan.image.build_spec import build_spec
from reposcan.image.builder import ImageBuilder, ensure_image
from reposcan.tools.install import current_platform

logger = logging.getLogger(__name__)


class ImageBuild(Action):
    name = "build"
    help = "Build the tool image on demand for the selected backend; reused if built."

    force: bool = flag(help="Rebuild even if an image for this spec exists.")

    def run(self) -> int:
        backend = select_backend(self.backend)
        if isinstance(backend, Failure):
            logger.error(backend.reason)
            return 2
        if not isinstance(backend, ContainerBackend):
            logger.error("the %s backend cannot build images", backend.name)
            return 2
        return build_image(backend.image_builder(), force=self.force)


class CacheList(Action):
    name = "list"
    help = "List the recorded image cache entries."

    def run(self) -> int:
        return list_cache()


class CacheRemove(Action):
    name = "remove"
    help = "Remove one entry by its image reference."

    reference: str = positional(help="The image reference to forget.")

    def run(self) -> int:
        return remove_cache_entry(self.reference)


class CacheClear(Action):
    name = "clear"
    help = "Remove all image cache entries."

    def run(self) -> int:
        return clear_cache()


def build_image(builder: ImageBuilder, *, force: bool) -> int:
    """Build (or reuse) the tool image with `builder`.

    Returns 0 with the image reference printed, or 1 if the build failed.
    """
    spec = build_spec(current_platform())
    result = ensure_image(builder, spec, force=force)
    if isinstance(result, Failure):
        logger.error(result.reason)
        return 1
    sys.stdout.write(f"{result}\n")
    return 0


def list_cache() -> int:
    """Print each recorded image cache entry as `reference  identity` to stdout."""
    entries = cache.entries()
    if not entries:
        logger.info("the image cache is empty")
        return 0
    width = max(len(reference) for reference in entries)
    for reference, identity in sorted(entries.items()):
        sys.stdout.write(f"{reference:<{width}}  {identity}\n")
    return 0


def remove_cache_entry(reference: str) -> int:
    """Remove `reference` from the image cache.

    Returns 0 when removed, 1 when it was not in the cache or the cache could not be
    written.
    """
    result = cache.remove(reference)
    if isinstance(result, Failure):
        logger.error(result.reason)
        return 1
    if not result:
        logger.error("no image cache entry for %s", reference)
        return 1
    logger.info("removed %s from the image cache", reference)
    return 0


def clear_cache() -> int:
    """Remove every image cache entry.

    Returns 0 on success, 1 if the cache could not be written.
    """
    count = len(cache.entries())
    error = cache.clear()
    if error is not None:
        logger.error(error.reason)
        return 1
    noun = "entry" if count == 1 else "entries"
    logger.info("cleared the image cache (%d %s)", count, noun)
    return 0


class CacheGroup(Group):
    name = "cache"
    help = "View or manage reposcan's record of built and pulled images."
    subcommands = (CacheList, CacheRemove, CacheClear)


class ImageGroup(Group):
    name = "image"
    help = "Build the tool image and manage the image cache."
    subcommands = (ImageBuild, CacheGroup)
