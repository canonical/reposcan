# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The resolution framework: a `PackageManager` Protocol and a `Resolver` base class.

A `Resolver` coordinates one ecosystem (Python, JS, Go): it discovers the directories
the ecosystem can resolve and drives resolution in each by composing
`PackageManager`s -- the specific tools within the ecosystem (uv, poetry, pipenv, npm,
pnpm). Each package manager resolves differently, so `PackageManager` is a Protocol;
the ecosystems all dispatch identically, so `Resolver` is a base class subclasses fill
in with a `name` and a `_managers` tuple.
"""

from abc import ABC
from collections.abc import Mapping
from typing import ClassVar, Protocol

from reposcan.execution.context import ExecutionContext


class PackageManager(Protocol):
    """A package manager within an ecosystem (uv, poetry, pipenv, npm, ...)."""

    def can_resolve(self, names: set[str]) -> bool:
        """Whether this package manager can resolve deps in a directory with `names`.

        Args:
            names: The file basenames in the directory.

        Returns:
            True if the directory holds a manifest this manager owns and no lock it
            would only reproduce.
        """
        ...

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Generate a lockfile in `workdir`.

        Args:
            ctx: The started context to run the package manager in.
            workdir: The directory's absolute path in the writable repo copy.
            names: The file basenames in `workdir`.
            tool_root: Where the tools are installed in the context.
            allow_code_execution: Permit building source packages
                (may run untrusted code).
        """
        ...


class Resolver(ABC):
    """Coordinates dependency resolution for an ecosystem.

    A subclass sets `name` and `_managers`; `find_roots` and `resolve` fan each
    directory out to every package manager that `can_resolve` it (a directory may hold
    manifests for more than one). This is a base class, not a Protocol, because every
    ecosystem shares this dispatch verbatim -- only the manager set differs.
    """

    name: ClassVar[str]
    _managers: ClassVar[tuple[PackageManager, ...]]

    def find_roots(self, tracked: Mapping[str, set[str]]) -> list[str]:
        """The directories at least one of the ecosystem's package managers resolves.

        Args:
            tracked: Each tracked directory mapped to the set of file basenames in it.

        Returns:
            The directories this ecosystem can resolve something in.
        """
        return sorted(
            directory
            for directory, names in tracked.items()
            if any(manager.can_resolve(names) for manager in self._managers)
        )

    def resolve(
        self,
        ctx: ExecutionContext,
        repo_dir: str,
        directory: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Run every package manager that can resolve `directory` in the copy.

        Args:
            ctx: The started context to run the resolvers in.
            repo_dir: The writable repo copy's path in the context.
            directory: The directory to resolve, relative to `repo_dir` ("" for root).
            names: The file basenames in `directory`.
            tool_root: Where the tools are installed in the context.
            allow_code_execution: Permit building source packages (runs untrusted code).
        """
        workdir = repo_dir if not directory else f"{repo_dir}/{directory}"
        for manager in self._managers:
            if manager.can_resolve(names):
                manager.resolve(
                    ctx,
                    workdir,
                    names,
                    tool_root,
                    allow_code_execution=allow_code_execution,
                )
