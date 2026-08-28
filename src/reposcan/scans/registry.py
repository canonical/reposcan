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
