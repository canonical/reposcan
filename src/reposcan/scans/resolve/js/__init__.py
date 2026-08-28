# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""JavaScript/TypeScript ecosystem resolver.

npm (package.json, covering npm/Yarn/Bun) and pnpm (`pnpm-workspace.yaml`) can each
apply to a directory. Each is a no-op when its manifest is absent or already locked.
"""

from reposcan.scans.resolve.interfaces import Resolver
from reposcan.scans.resolve.js.npm import Npm
from reposcan.scans.resolve.js.pnpm import Pnpm


class JsResolver(Resolver):
    """Resolves JavaScript/TypeScript dependencies (npm, pnpm)."""

    name = "javascript"
    _managers = (Npm(), Pnpm())
