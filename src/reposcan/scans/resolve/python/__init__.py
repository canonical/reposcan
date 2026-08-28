# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Python ecosystem resolver.

uv (PEP 621 / `requirements*` / `setup.cfg`), Poetry (legacy `[tool.poetry]`), and
Pipenv (`Pipfile`) can each apply to a directory independently. Each is a no-op when
its manifest is absent, the wrong flavor, or already locked.
"""

from reposcan.scans.resolve.interfaces import Resolver
from reposcan.scans.resolve.python.pipenv import Pipenv
from reposcan.scans.resolve.python.poetry import Poetry
from reposcan.scans.resolve.python.uv import Uv


class PythonResolver(Resolver):
    """Resolves Python dependencies (uv, Poetry, Pipenv)."""

    name = "python"
    _managers = (Uv(), Poetry(), Pipenv())
