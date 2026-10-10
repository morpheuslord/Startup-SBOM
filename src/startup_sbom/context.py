"""Scan options and the per-scan context shared by all analysis stages."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from startup_sbom.models import ContainerInfo, OSInfo
from startup_sbom.rootfs import RootFS

log = logging.getLogger("startup_sbom")


@dataclass(slots=True)
class ScanOptions:
    """User-controllable behaviour of a scan.  Defaults are safe and offline-friendly."""

    # data sources
    offline: bool = False
    vuln_sources: tuple[str, ...] = ("osv",)  # osv | arch | nvd
    nvd_api_key: str | None = None
    epss: bool = True
    kev: bool = True
    eol: bool = True
    cache_dir: Path | None = None
    http_timeout: float = 30.0
    # analysis depth
    language_packages: bool = True
    link_analysis: bool = True
    integrity_check: bool = False
    max_link_depth: int = 8
    # target selection
    platform: str | None = None  # os/arch[/variant] for multi-platform images
    boot_timing_file: Path | None = None  # `systemd-analyze plot` SVG or `blame` text
    # threat semantics
    vex_not_affected_unreachable: bool = False
    max_chains: int = 25


@dataclass(slots=True)
class ScanContext:
    """Everything a stage may consult.  Stages must treat ``fs`` as read-only/untrusted."""

    fs: RootFS
    options: ScanOptions = field(default_factory=ScanOptions)
    os: OSInfo = field(default_factory=OSInfo)
    container: ContainerInfo | None = None
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        """Record a non-fatal problem; it is logged and included in the report."""
        log.warning("%s", message)
        self.warnings.append(message)

    def limit(self, message: str) -> None:
        """Record a coverage limitation (something the scan could not assess)."""
        log.info("limitation: %s", message)
        if message not in self.limitations:
            self.limitations.append(message)
