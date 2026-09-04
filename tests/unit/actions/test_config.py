# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for `reposcan config`.

Each test points config.CONFIG_FILE at a temp dir so it never touches a real
~/.config/reposcan/config.json.
"""

import io
import pathlib
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout

import reposcan.config as config
from reposcan.app import main
from reposcan.config import load


@contextmanager
def _isolated_config() -> Iterator[None]:
    """Point config.CONFIG_FILE at a fresh temp dir for the duration of the block."""
    saved = config.CONFIG_FILE
    with tempfile.TemporaryDirectory() as tmp:
        config.CONFIG_FILE = pathlib.Path(tmp) / "reposcan" / "config.json"
        try:
            yield
        finally:
            config.CONFIG_FILE = saved


def test_set_validates_the_key_and_value_before_persisting() -> None:
    with _isolated_config():
        assert main(["config", "set", "bogus", "x"]) == 2  # unknown key
        assert main(["config", "set", "backend", "podman"]) == 2  # invalid value
        assert load() == {}  # nothing persisted on rejection
        assert main(["config", "set", "backend", "lxd"]) == 0  # a valid value is stored
        assert load() == {"backend": "lxd"}


def test_image_key_accepts_any_non_empty_reference() -> None:
    with _isolated_config():
        assert main(["config", "set", "image", "   "]) == 2  # blank is rejected
        assert main(["config", "set", "image", "canonical"]) == 0  # shorthand accepted
        assert load()["image"] == "canonical"


def test_unset_removes_a_key_and_is_idempotent() -> None:
    with _isolated_config():
        main(["config", "set", "image", "canonical"])
        assert main(["config", "unset", "image"]) == 0
        assert load() == {}
        assert main(["config", "unset", "image"]) == 0  # already absent: still success


def test_get_prints_a_set_value_and_reports_a_missing_one() -> None:
    with _isolated_config():
        main(["config", "set", "backend", "docker"])
        out = io.StringIO()
        with redirect_stdout(out):
            assert main(["config", "get", "backend"]) == 0
        assert out.getvalue().strip() == "docker"
        assert main(["config", "get", "uid"]) == 1  # known key, not set
