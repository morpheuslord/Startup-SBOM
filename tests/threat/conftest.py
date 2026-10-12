"""Make the threat-test factory importable and provide a ScanContext fixture."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.rootfs import DirectoryRootFS


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    """A context whose RootFS points at an empty directory (threat analysis never reads it)."""
    root = tmp_path / "root"
    root.mkdir()
    return ScanContext(fs=DirectoryRootFS(root), options=ScanOptions(offline=True))
