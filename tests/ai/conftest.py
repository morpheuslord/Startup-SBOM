"""Fixtures for the AI-layer tests (all skipped when the 'ai' extra is not installed).

No test ever talks to a real model API.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

sys.path.insert(0, str(Path(__file__).parent.parent / "report"))  # reportdata fixture
sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

import pydantic_ai.models as pai_models
from reportdata import build_report

from startup_sbom.ai.index import ReportIndex
from startup_sbom.models import Report


@pytest.fixture(autouse=True)
def no_model_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hard guarantee: no test can reach a real provider API."""
    monkeypatch.setattr(pai_models, "ALLOW_MODEL_REQUESTS", False)
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "OPENROUTER_API_KEY",
        "OLLAMA_BASE_URL",
        "STARTUP_SBOM_AI_PLUGINS",
        "STARTUP_SBOM_AI_AGENT_URLS",
        "STARTUP_SBOM_AGENT_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def report() -> Report:
    return build_report()


@pytest.fixture
def hostile_report() -> Report:
    return build_report(hostile=True)


@pytest.fixture
def index(report: Report) -> ReportIndex:
    return ReportIndex(report)
