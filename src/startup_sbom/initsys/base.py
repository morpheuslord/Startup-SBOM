"""Interface shared by all init-system / service-manager analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from startup_sbom.context import ScanContext
from startup_sbom.models import InitSystem, Service


class InitAnalyzer(ABC):
    """Discovers what a service manager would start, by reading configuration only.

    Analyzers fill :class:`~startup_sbom.models.Service` objects including
    ``commands`` with *resolved, canonical in-image* ``executable`` paths,
    ``activation``, ``hardening`` and ``listens``.  Package ownership
    (``Service.packages``) is filled later by the pipeline.
    """

    name: InitSystem

    @abstractmethod
    def detect(self, ctx: ScanContext) -> bool:
        """Return ``True`` if this service manager is configured in ``ctx.fs``."""

    @abstractmethod
    def discover(self, ctx: ScanContext) -> list[Service]:
        """Return every configured service (started automatically or not)."""
