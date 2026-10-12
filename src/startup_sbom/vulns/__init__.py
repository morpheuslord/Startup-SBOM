"""Vulnerability matching: OSV.dev (distro-aware), Arch tracker, opt-in NVD CPE,
enriched with FIRST EPSS and CISA KEV.

Entry points: :func:`match_vulnerabilities`, :func:`update_feeds`, :func:`feed_status`
and :func:`startup_sbom.vulns.versions.compare`.
"""

from __future__ import annotations

from startup_sbom.vulns.arch import ArchTrackerSource
from startup_sbom.vulns.base import VulnerabilitySource
from startup_sbom.vulns.match import enrich, feed_status, match_vulnerabilities, update_feeds
from startup_sbom.vulns.nvd import NvdSource
from startup_sbom.vulns.osv import OsvSource

__all__ = [
    "ArchTrackerSource",
    "NvdSource",
    "OsvSource",
    "VulnerabilitySource",
    "enrich",
    "feed_status",
    "match_vulnerabilities",
    "update_feeds",
]
