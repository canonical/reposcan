# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan image` group: build the image and manage the image cache."""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.backends import select_backend
from reposcan.cli_kit import Group, flag, positional
from reposcan.image import cache as image_cache
from reposcan.result import Err, is_err
from reposcan.table import render_table

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
        """Print each recorded image cache entry as a table."""
        entries = image_cache.load()
        if not entries:
            logger.info("the image cache is empty")
            return 0
        rows = [[ref, identity] for ref, identity in sorted(entries.items())]
        sys.stdout.write(render_table(["reference", "identity"], rows))
        return 0


class CacheRemove(Action):
    name = "remove"
    help = "Remove one entry by its image reference."

    reference: str = positional(help="The image reference to forget.")

    def run(self) -> int:
        """Remove `self.reference` from the image cache.

        Returns:
            0 when removed, 1 when it was not in the cache or the cache could not be
            written.
        """
        removed = image_cache.remove(self.reference)
        if isinstance(removed, Err):
            logger.error(removed.msg)
            return 1
        if not removed:
            logger.error("no image cache entry for %s", self.reference)
            return 1
        logger.info("removed %s from the image cache", self.reference)
        return 0


class CacheClear(Action):
    name = "clear"
    help = "Remove all image cache entries."

    def run(self) -> int:
        """Remove every image cache entry.

        Returns:
            0 on success, 1 when the cache could not be written.
        """
        count = len(image_cache.load())
        if is_err(err := image_cache.clear()):
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
