"""Scan options and the per-scan context shared by all analysis stages."""

from __future__ import annotations

import logging
from collections.abc import Callable
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
    derivative_fallback: bool = True  # rolling Debian derivatives -> Debian testing advisories
    eol: bool = True
    cache_dir: Path | None = None
    http_timeout: float = 30.0
    # analysis depth
    language_packages: bool = True
    link_analysis: bool = True
    integrity_check: bool = False
    max_link_depth: int = 8
    # target selection
    #: ``static`` reads files only; ``chroot`` additionally runs the target's own tools
    #: in an unprivileged read-only sandbox; ``auto`` picks chroot when it is possible.
    mode: str = "static"
    platform: str | None = None  # os/arch[/variant] for multi-platform images
    boot_timing_file: Path | None = None  # `systemd-analyze plot` SVG or `blame` text
    # threat semantics
    vex_not_affected_unreachable: bool = False
    #: A CVSS vector with I:N/A:N (confidentiality only) never yields code execution
    #: or privilege gain, whatever the CWE or advisory wording suggests.
    cvss_impact_gate: bool = True
    max_chains: int = 25
    # online intel prefetch (opt-in; respects ``offline``)
    prefetch_intel: bool = False
    intel_max_cves: int = 25
    intel_max_articles: int = 4
    intel_budget: float = 120.0
    intel_articles: bool = True


@dataclass(slots=True)
class ScanContext:
    """Everything a stage may consult.  Stages must treat ``fs`` as read-only/untrusted."""

    fs: RootFS
    options: ScanOptions = field(default_factory=ScanOptions)
    os: OSInfo = field(default_factory=OSInfo)
    container: ContainerInfo | None = None
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    vuln_sources_used: set[str] = field(default_factory=set)
    """Vulnerability sources that were actually consulted for this target (an enabled
    source with no applicable packages, e.g. ``arch`` on a Debian system, is absent)."""
    on_warning: Callable[[str], None] | None = field(default=None, repr=False)
    """Live-display hook called with every warning (set by the pipeline)."""

    def warn(self, message: str) -> None:
        """Record a non-fatal problem; it is logged and included in the report."""
        log.warning("%s", message)
        self.warnings.append(message)
        if self.on_warning is not None:
            self.on_warning(message)

    def limit(self, message: str) -> None:
        """Record a coverage limitation (something the scan could not assess)."""
        log.info("limitation: %s", message)
        if message not in self.limitations:
            self.limitations.append(message)
