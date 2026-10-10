"""Fixtures for the report renderer tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from reportdata import build_report

from startup_sbom.models import Report


@pytest.fixture
def report() -> Report:
    return build_report()


@pytest.fixture
def hostile_report() -> Report:
    return build_report(hostile=True)


@pytest.fixture
def container_report() -> Report:
    return build_report(container=True)
