"""Interface shared by vulnerability data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

from startup_sbom.context import ScanContext
from startup_sbom.models import Package, Vulnerability


class VulnerabilitySource(ABC):
    """A provider that matches installed packages against advisory data."""

    name: str

    @abstractmethod
    def applicable(self, ctx: ScanContext, packages: list[Package]) -> list[Package]:
        """Subset of ``packages`` this source can assess for the detected OS."""

    @abstractmethod
    def match(self, ctx: ScanContext, packages: list[Package]) -> list[Vulnerability]:
        """Return vulnerabilities affecting ``packages`` (status ``affected`` or similar)."""
