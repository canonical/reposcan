# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the image build spec (reposcan.image.build_spec)."""

from reposcan.image.build_spec import BuildSpec, build_spec
from reposcan.tools.model import Platform

_LINUX = Platform("linux", "amd64")


def test_digest_is_content_addressed() -> None:
    spec = build_spec(_LINUX)
    assert spec.digest == build_spec(_LINUX).digest  # stable for the same inputs
    # Any change to an identity input yields a new digest.
    assert spec.digest != build_spec(Platform("linux", "arm64")).digest  # platform
    assert spec.digest != build_spec(_LINUX, base_image="ubuntu:22.04").digest  # base
    edited = BuildSpec(spec.base_image, spec.install_root, spec.script + "\n# x")
    assert edited.digest != spec.digest  # script
