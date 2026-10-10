"""Interfaces shared by all package database readers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from startup_sbom.context import ScanContext
from startup_sbom.models import Package, PackageType


@dataclass(slots=True)
class PackageRecord:
    """A package plus the data needed for ownership and integrity analysis.

    ``files`` are absolute in-image paths *exactly as recorded* by the database
    (not canonicalised; ``/bin/ip`` may really live at ``/usr/bin/ip``).
    ``digests`` maps a recorded path to ``"<algo>:<hex>"`` when the database has it.
    """

    package: Package
    files: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)
    conffiles: list[str] = field(default_factory=list)


class PackageDatabase(ABC):
    """Reader for one package database format.  Must be pure Python and read-only."""

    #: short identifier, e.g. ``"dpkg"``
    name: str
    package_type: PackageType

    @abstractmethod
    def detect(self, ctx: ScanContext) -> bool:
        """Return ``True`` if this database is present in ``ctx.fs``."""

    @abstractmethod
    def read(self, ctx: ScanContext) -> list[PackageRecord]:
        """Parse every installed package.  Never raise on a single malformed entry."""
