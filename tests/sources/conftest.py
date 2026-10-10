"""Fixtures for target acquisition tests."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture
def scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ``tempfile`` into a private directory so leaks are observable."""
    d = tmp_path / "scratch"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d
