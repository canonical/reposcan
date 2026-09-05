# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan image` group: build the image and manage the image cache."""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.backends import select_backend
from reposcan.cli_kit import Group, flag, positional
from reposcan.image import cache
from reposcan.result import Err, is_err

logger = logging.getLogger(__name__)


class ImageBuild(Action):
    name = "build"
    help = "Build the reposcan image for the selected backend (it is reused if built)."

    force: bool = flag(help="Rebuild even if an image for this spec exists.")

    def run(self) -> int:
        """Build (or reuse) the reposcan image and print its reference."""
        backend = select_backend(self.backend)
        if isinstance(backend, Err):
            logger.error(backend.msg)
            return 2
        if not backend.containerized:
            logger.error("the %s backend cannot build images", backend.name)
            return 2
        built = backend.build_image(force=self.force)
        if isinstance(built, Err):
            logger.error(built.msg)
            return 1
        sys.stdout.write(f"{built}\n")
        return 0


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


def list_cache() -> int:
    """Print each recorded image cache entry as `reference  identity` to stdout."""
    entries = cache.load()
    if not entries:
        logger.info("the image cache is empty")
        return 0
    width = max(len(reference) for reference in entries)
    for reference, identity in sorted(entries.items()):
        sys.stdout.write(f"{reference:<{width}}  {identity}\n")
    return 0


def remove_cache_entry(reference: str) -> int:
    """Remove `reference` from the image cache.

    Returns:
        0 when removed, 1 when it was not in the cache or the cache could not be
        written.
    """
    removed = cache.remove(reference)
    if isinstance(removed, Err):
        logger.error(removed.msg)
        return 1
    if not removed:
        logger.error("no image cache entry for %s", reference)
        return 1
    logger.info("removed %s from the image cache", reference)
    return 0


def clear_cache() -> int:
    """Remove every image cache entry.

    Returns:
        0 on success, 1 when the cache could not be written.
    """
    count = len(cache.load())
    if is_err(err := cache.clear()):
        logger.error(err.msg)
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
    help = "Build the reposcan image and manage the image cache."
    subcommands = (ImageBuild, CacheGroup)
