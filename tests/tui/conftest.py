"""Fixtures for the TUI tests (all skipped when the 'tui' extra is not installed)."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

pytest.importorskip("textual")

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "report"))

from reportdata import build_report

from startup_sbom.models import Report
from startup_sbom.tui import integrations
from startup_sbom.tui.app import StartupSbomApp


@pytest.fixture(autouse=True)
def no_optional_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional integrations (viz/explain/intel/ai) are absent unless a test opts in."""
    monkeypatch.setattr(integrations, "optional_module", lambda name: None)


@pytest.fixture
def report() -> Report:
    return build_report()


@pytest.fixture
def hostile_report() -> Report:
    return build_report(hostile=True)


@pytest.fixture
def make_app(tmp_path: Path) -> Callable[..., StartupSbomApp]:
    """App factory with an isolated recent-scans store and a stubbed container lister."""

    def _make(**kw: object) -> StartupSbomApp:
        kw.setdefault("data_dir", tmp_path / "tui-data")
        kw.setdefault("container_lister", lambda engine: [])
        kw.setdefault("start_dir", tmp_path)
        return StartupSbomApp(**kw)  # type: ignore[arg-type]

    return _make
