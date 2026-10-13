"""Agentic AI analysis over a finished scan report (optional ``ai`` extra).

The deterministic report stays the source of truth.  Agents only *read* it through
paged, size-capped, spotlighted tools, every output is machine-checked against the
report ids and numbers (:mod:`startup_sbom.ai.grounding`), and the result is an
:class:`~startup_sbom.models.AIAssessment` stored in ``report.ai``::

    from startup_sbom.ai import analyze

    report.ai = analyze(report, profile="cheap", max_cost_usd=0.50)

Importing this package is cheap: ``pydantic_ai``, ``mcp`` and ``fasta2a`` are only
imported by the submodules that need them, with a friendly error when the extra
is missing.
"""

from __future__ import annotations

import importlib
import os
from typing import TYPE_CHECKING, Any

from startup_sbom.errors import StartupSBOMError

if TYPE_CHECKING:
    from startup_sbom.ai.orchestrator import analyze, analyze_async
    from startup_sbom.ai.outputs import render_assessment
    from startup_sbom.ai.providers import available_providers

__all__ = [
    "AIBudgetError",
    "AIConfigError",
    "AIError",
    "AIUnavailableError",
    "analyze",
    "analyze_async",
    "available_providers",
    "render_assessment",
    "require",
]

# pydantic-ai prints an observability banner on stderr at the first run; it would tear
# through the live scan dashboard and the TUI.  The user can still opt back in.
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

INSTALL_HINT = "pip install 'startup-sbom[ai]'"
SERVER_INSTALL_HINT = "pip install 'startup-sbom[agents-server]'"


class AIError(StartupSBOMError):
    """Base class for errors raised by the AI layer."""


class AIUnavailableError(AIError):
    """An optional dependency of the AI layer is not installed."""


class AIConfigError(AIError):
    """Provider, model, agent or server configuration is invalid."""


class AIBudgetError(AIError):
    """A run hit its usage limits or its ``max_cost_usd`` guard."""


def require(module: str, *, hint: str = INSTALL_HINT) -> Any:
    """Import ``module`` or raise :class:`AIUnavailableError` naming the extra to install."""
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise AIUnavailableError(
            f"the AI features need the optional dependency "
            f"{module.split('.', maxsplit=1)[0]!r}: {hint}"
        ) from exc


_LAZY = {
    "analyze": "startup_sbom.ai.orchestrator",
    "analyze_async": "startup_sbom.ai.orchestrator",
    "render_assessment": "startup_sbom.ai.outputs",
    "available_providers": "startup_sbom.ai.providers",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(name)
    return getattr(importlib.import_module(module), name)
