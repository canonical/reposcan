# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The SBOM scan: build a software bill of materials with trivy, syft, and cdxgen.

Each tool emits CycloneDX; the components are merged into one deduped SBOM,
annotated with which scanners reported each (see scans/cyclonedx.py `merge`).

cdxgen runs in a no-build, secure mode so it never executes the scanned repo's own
code (see the invocation), and writes its BOM to a file that run_scan reads back --
cdxgen interleaves progress logs on stdout, so stdout is not a reliable channel. It
stays optional: if it fails, trivy + syft still produce the SBOM.
"""

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.scans.base import DependencyResolvingScan
from repo_scanner.scans.model import ToolInvocation

# Where cdxgen writes its BOM inside the (ephemeral) scan container; run_scan reads it.
_CDXGEN_OUTPUT = "/tmp/cdxgen-sbom.json"


class SbomScan(DependencyResolvingScan):
    """Build a software bill of materials for a repository's components."""

    name = "sbom"
    help = "Software bill of materials."

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The trivy, syft, and cdxgen invocations for `target`.

        Args:
            ctx: The started context (unused).
            target: The repository path as seen in the execution context.

        Returns:
            One invocation per tool. trivy and syft emit CycloneDX on stdout; cdxgen
            writes to a file (read back by run_scan) and runs in a no-build, secure
            mode. cdxgen is optional.
        """
        # by default, cdxgen includes development dependencies while trivy and syft
        # exclude them.
        trivy_args = ["fs", "--skip-version-check", "--format", "cyclonedx"]
        syft_env = {
            # see https://github.com/anchore/syft/wiki/file-selection
            "SYFT_FILE_METADATA_SELECTION": "none",
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
            # Capture requirements.txt entries that carry a version constraint but no
            # exact pin (e.g. "flask>=2.0"); syft drops them otherwise. Note: no SBOM
            # tool reads pyproject.toml deps in our no-install mode -- see
            # docs/explanation/sbom-generation.md.
            "SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS": "true",
        }
        syft_args = [
            f"dir:{target}",
            "-o",
            "cyclonedx-json",
            # Broaden beyond syft's default directory catalogers
            "--override-default-catalogers",
            "all",
        ]
        # --no-install-deps (and the pre-build lifecycle) keep cdxgen to static
        # manifest/lockfile parsing, so it never runs the repo's setup.py/build backend.
        cdxgen_args = ["--no-install-deps", "--lifecycle", "pre-build", "--no-banner"]
        if self.include_dev_dependencies:
            trivy_args.append("--include-dev-deps")
            syft_env["SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES"] = "true"
        else:
            cdxgen_args.append("--required-only")
        trivy_args.append(target)
        cdxgen_args += ["-o", _CDXGEN_OUTPUT, target]

        return [
            ToolInvocation("trivy", trivy_args),
            ToolInvocation(
                tool="syft",
                args=syft_args,
                env=syft_env,
            ),
            ToolInvocation(
                "cdxgen",
                cdxgen_args,
                # CDXGEN_SECURE_MODE is defense-in-depth: if any code path still tried
                # to install, cdxgen would inject python -S and pip --only-binary.
                env={"CDXGEN_SECURE_MODE": "true"},
                output_file=_CDXGEN_OUTPUT,
                optional=True,
            ),
        ]
