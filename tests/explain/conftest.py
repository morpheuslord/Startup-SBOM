"""Shared fixtures: make the threat-test factory importable and provide a context."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "threat"))
sys.path.insert(0, str(Path(__file__).parent))

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.rootfs import DirectoryRootFS


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    """A context over an empty root (the explanation layer never reads the target)."""
    root = tmp_path / "root"
    root.mkdir()
    return ScanContext(fs=DirectoryRootFS(root), options=ScanOptions(offline=True))
