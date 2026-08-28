# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared utils for the fixture tests."""

import importlib
import importlib.util
import logging
import pkgutil
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import reposcan.scans as scans_pkg
from reposcan.backends import DockerBackend, Session, start_session
from reposcan.execution.context import host_user
from reposcan.scans.base import Scan

logger = logging.getLogger(__name__)

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> ModuleType:
    """The fixture module at fixtures/<name>.py (it exposes SCAN, plant, verify)."""
    path = _FIXTURES_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_scan_fixture_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_names() -> set[str]:
    """The name (file stem) of every fixture under fixtures/."""
    return {p.stem for p in _FIXTURES_DIR.glob("*.py") if not p.stem.startswith("_")}


def discover_scans() -> dict[str, type[Scan]]:
    """Every concrete Scan defined under src/reposcan/scans, keyed by name."""
    scans: dict[str, type[Scan]] = {}
    for info in pkgutil.iter_modules(scans_pkg.__path__):
        module = importlib.import_module(f"{scans_pkg.__name__}.{info.name}")
        for obj in vars(module).values():
            # A concrete scan defined in this module (not imported, not a base): a
            # Scan subclass that sets its own `name` (the bases do not).
            defined_here = isinstance(obj, type) and obj.__module__ == module.__name__
            if defined_here and issubclass(obj, Scan) and hasattr(obj, "name"):
                scans[obj.name] = obj
    return scans


def require_docker() -> None:
    """Fail (never skip) when docker is unavailable -- fixtures must run for real."""
    availability = DockerBackend().availability()
    assert availability.ok, f"docker unavailable: {availability.reason}"


@contextmanager
def planted_session(name: str, plant: Callable[[Path], None]) -> Iterator[Session]:
    """A started docker tool session over a temp repo that `plant` has populated."""
    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory)
        plant(repo)
        logger.info("[docker] scanning the %s fixture", name)
        with start_session(
            "docker",
            tool_image=True,
            mount_source=str(repo),
            user=host_user(),
            image="build",
        ) as session:
            assert session.ok, f"session failed for {name} (exit {session.exit_code})"
            assert session.target is not None
            yield session
