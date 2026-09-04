# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scan types the `scan` command can run."""

from reposcan.scans.base import SecurityScan
from reposcan.scans.iac import IacScan
from reposcan.scans.sast import SastScan
from reposcan.scans.sca import ScaScan
from reposcan.scans.secrets import SecretsScan
from reposcan.scans.workflow import WorkflowScan

SCANS: dict[str, type[SecurityScan]] = {
    "secrets": SecretsScan,
    "sast": SastScan,
    "iac": IacScan,
    "workflow": WorkflowScan,
    "sca": ScaScan,
}


def parse_scan_names(name_string: str) -> list[str]:
    """Split comma-separated `name_string` into scan-type names.

    The meta-name `all` expands to every scan type.
    """
    names: list[str] = []
    for token in name_string.split(","):
        name = token.strip()
        if not name:
            continue
        if name == "all":
            selected = list(SCANS)
        elif name in SCANS:
            selected = [name]
        else:
            valid = ", ".join([*SCANS, "all"])
            raise ValueError(f"unknown scan type {name!r} (choose from: {valid})")
        for chosen in selected:
            if chosen not in names:
                names.append(chosen)
    if not names:
        raise ValueError("give at least one scan type")
    return names
