# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scan types the `scan` command can run."""

from repo_scanner.scans.base import Scan
from repo_scanner.scans.iac import IacScan
from repo_scanner.scans.sast import SastScan
from repo_scanner.scans.sca import ScaScan
from repo_scanner.scans.secrets import SecretsScan
from repo_scanner.scans.workflow import WorkflowScan

# Every findings scan type, keyed by its command-line name, in help/run order.
SCANS: dict[str, type[Scan]] = {
    "secrets": SecretsScan,
    "sast": SastScan,
    "iac": IacScan,
    "workflow": WorkflowScan,
    "sca": ScaScan,
}
