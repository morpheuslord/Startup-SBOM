"""Opt-in online intel prefetch for findings: advisories, exploits, PoCs and articles.

Structured, allow-listed feeds come first (CVE Services / CISA Vulnrichment, vendor
JSON, EPSS, exploit indexes, PoC-in-GitHub metadata); third-party articles are only
fetched through the SSRF-hardened :class:`~startup_sbom.intel.fetcher.SafeFetcher`
and are always treated as untrusted data.
"""

from __future__ import annotations

from startup_sbom.intel.exploits import update_index
from startup_sbom.intel.prefetch import article_text, lookup, prefetch
from startup_sbom.intel.render import SYSTEM_RULES, agent_context, untrusted_block

ATTRIBUTIONS: list[str] = [
    "CVE records: CVE Program / MITRE, used under the CVE Terms of Use.",
    "This product uses the NVD API but is not endorsed or certified by the NVD.",
    "EPSS scores: FIRST.org Exploit Prediction Scoring System (https://www.first.org/epss).",
    "CISA Known Exploited Vulnerabilities catalog and CISA Vulnrichment (CC0).",
    "GitHub Advisory Database (CC BY 4.0).",
    "Red Hat security data (CC BY 4.0, per publisher).",
    "Ubuntu CVE data: Canonical Ltd. (facts and links only).",
    "Exploit-DB: OffSec (metadata and links only; repository GPL-2.0, no exploit code stored).",
    "Metasploit Framework module metadata: Rapid7 (BSD-3-Clause).",
    "nuclei-templates: ProjectDiscovery (MIT).",
    "PoC-in-GitHub: nomi-sec (CC0); repository metadata only, never cloned or executed.",
    "Third-party articles: snippets and links only; full text stays in the local cache.",
]

__all__ = [
    "ATTRIBUTIONS",
    "SYSTEM_RULES",
    "agent_context",
    "article_text",
    "lookup",
    "prefetch",
    "untrusted_block",
    "update_index",
]
