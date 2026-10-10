"""CISA Known Exploited Vulnerabilities catalog (JSON feed)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from startup_sbom.errors import NetworkError
from startup_sbom.models import KEVInfo
from startup_sbom.net import HttpClient
from startup_sbom.vulns.normalize import is_cve

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_TTL = 24 * 3600.0


@dataclass(slots=True)
class KevCatalog:
    """Parsed catalog: ``entries`` maps CVE id to :class:`KEVInfo`."""

    entries: dict[str, KEVInfo] = field(default_factory=dict)
    version: str | None = None
    released: str | None = None


def _opt(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def parse_kev(data: bytes) -> KevCatalog:
    """Parse the KEV JSON feed; malformed entries are skipped."""
    try:
        doc = json.loads(data)
    except ValueError as exc:
        raise NetworkError("kev: malformed catalog") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise NetworkError("kev: unexpected catalog format")
    cat = KevCatalog(
        version=_opt(doc.get("catalogVersion")), released=_opt(doc.get("dateReleased"))
    )
    for item in doc["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve = _opt(item.get("cveID"))
        if not cve or not is_cve(cve):
            continue
        cat.entries[cve] = KEVInfo(
            date_added=_opt(item.get("dateAdded")),
            due_date=_opt(item.get("dueDate")),
            ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            required_action=_opt(item.get("requiredAction")),
            vendor_project=_opt(item.get("vendorProject")),
            product=_opt(item.get("product")),
        )
    return cat


def load_kev(http: HttpClient, *, force: bool = False) -> KevCatalog:
    """Catalog from cache (24 h TTL) or ``www.cisa.gov``; ``force`` revalidates."""
    resp = http.get(KEV_URL, ttl=0.0 if force else KEV_TTL)
    return parse_kev(resp.content)
