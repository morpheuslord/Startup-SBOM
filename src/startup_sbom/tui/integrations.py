"""Defensive, lazy bridges to optional modules (viz, explain, intel, ai, pdf).

Each bridge imports its module on first use and degrades gracefully: a missing
module or extra returns ``None`` (or raises :class:`FeatureUnavailableError` for
explicit user actions) instead of crashing the TUI.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

from rich.console import RenderableType

from startup_sbom.errors import StartupSBOMError
from startup_sbom.models import AIAssessment, Explanations, IntelBundle, IntelRecord, Report
from startup_sbom.tui.state import AISettings

log = logging.getLogger("startup_sbom.tui")

VIZ_MODULE = "startup_sbom.viz.terminal"
EXPLAIN_MODULE = "startup_sbom.explain"
INTEL_MODULE = "startup_sbom.intel"
AI_MODULE = "startup_sbom.ai"


class FeatureUnavailableError(StartupSBOMError):
    """An optional feature's module or extra is not installed."""


def optional_module(name: str) -> ModuleType | None:
    """Import ``name`` or return ``None`` when it (or one of its dependencies) is missing."""
    try:
        return importlib.import_module(name)
    except ImportError:
        return None
    except Exception:  # a half-written optional module must never sink the UI
        log.debug("optional module %s failed to import", name, exc_info=True)
        return None


def _function(module: str, name: str) -> Callable[..., Any] | None:
    mod = optional_module(module)
    fn = getattr(mod, name, None) if mod is not None else None
    return fn if callable(fn) else None


def viz(name: str, *args: object) -> RenderableType | None:
    """Call ``startup_sbom.viz.terminal.<name>(*args)``; ``None`` if absent or failing."""
    fn = _function(VIZ_MODULE, name)
    if fn is None:
        return None
    try:
        result = fn(*args)
    except Exception:
        log.debug("viz %s failed", name, exc_info=True)
        return None
    return result if result is not None else None


def viz_available() -> bool:
    """Whether the terminal visualisation module is importable."""
    return optional_module(VIZ_MODULE) is not None


def explain(report: Report) -> Explanations | None:
    """Run ``explain_report`` (may also fill ``Threat.explanation`` in place)."""
    fn = _function(EXPLAIN_MODULE, "explain_report")
    if fn is None:
        return None
    result = fn(report)
    if isinstance(result, Explanations):
        return result
    if isinstance(result, Report):
        return result.explanations
    return report.explanations


def intel_available() -> bool:
    """Whether the intel module offers ``lookup``."""
    return _function(INTEL_MODULE, "lookup") is not None


def intel_lookup(cve: str, *, offline: bool = False, cache_dir: Path | None = None) -> IntelBundle:
    """Fetch intel for one CVE (blocking; run it off the event loop)."""
    fn = _function(INTEL_MODULE, "lookup")
    if fn is None:
        raise FeatureUnavailableError("intel lookup is not available in this installation")
    if offline:
        raise FeatureUnavailableError("intel lookup needs network access (offline mode)")
    from startup_sbom.net import HttpClient

    with HttpClient(offline=offline, cache_dir=cache_dir) as http:
        result = fn(cve, http, articles=True)
    if isinstance(result, IntelBundle):
        return result
    return IntelBundle.model_validate(result)


def article_text(record: IntelRecord) -> str | None:
    """Cached cleaned article text (``None`` when unavailable)."""
    fn = _function(INTEL_MODULE, "article_text")
    if fn is None:
        return None
    try:
        text = fn(record)
    except Exception:
        log.debug("article_text failed", exc_info=True)
        return None
    return text if isinstance(text, str) else None


def ai_available() -> bool:
    """Whether the AI analyst module is importable."""
    return _function(AI_MODULE, "analyze") is not None


def ai_providers() -> dict[str, bool]:
    """``provider → configured`` from ``ai.available_providers()`` (empty when absent)."""
    fn = _function(AI_MODULE, "available_providers")
    if fn is None:
        return {}
    try:
        result = fn()
    except Exception:
        log.debug("available_providers failed", exc_info=True)
        return {}
    if not isinstance(result, dict):
        return {}
    return {str(k): bool(v) for k, v in result.items()}


def ai_analyze(
    report: Report, settings: AISettings, stream: Callable[[object], None] | None = None
) -> AIAssessment:
    """Run the AI analyst (blocking; run it off the event loop)."""
    fn = _function(AI_MODULE, "analyze")
    if fn is None:
        raise FeatureUnavailableError(
            "AI analysis is not installed: pip install 'startup-sbom[ai]'"
        )
    result = fn(
        report,
        provider=settings.provider,
        model=settings.model,
        profile=settings.profile,
        audience=settings.audience,
        max_cost_usd=settings.max_cost_usd,
        stream=stream,
    )
    if isinstance(result, AIAssessment):
        return result
    return AIAssessment.model_validate(result)
