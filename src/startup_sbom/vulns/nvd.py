"""Opt-in NVD API 2.0 fallback: CPE range matching for packages no other source covers.

Never a keyword search.  For each package CPE the product-level
``virtualMatchString`` is queried with the installed version as range bound, then
every returned CVE's configurations are re-checked locally.  Distro backports are
invisible to CPE data, so results always carry ``low`` confidence.  The API key
travels only in the ``apiKey`` header; requests are paced to NVD's published
limits (5 / 30 s without a key, 50 / 30 s with one).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from startup_sbom.context import ScanContext
from startup_sbom.errors import NetworkError
from startup_sbom.models import Confidence, Package, Vulnerability, VulnStatus
from startup_sbom.net import HttpClient
from startup_sbom.vulns.base import VulnerabilitySource
from startup_sbom.vulns.normalize import (
    MAX_REFERENCES,
    Fragment,
    merge_vulnerabilities,
    normalise_cwe,
    parse_cvss,
    resolve_severity,
    sort_cvss,
    sort_cwes,
    truncate,
    unique,
)
from startup_sbom.vulns.versions import rpmvercmp

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TTL = 24 * 3600.0
RESULTS_PER_PAGE = 2000
MAX_PAGES = 10
DELAY_WITH_KEY = 0.7
DELAY_WITHOUT_KEY = 6.5
_CPE_SPLIT = re.compile(r"(?<!\\):")
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def parse_cpe(cpe: str) -> dict[str, str] | None:
    """Split a CPE 2.3 formatted string into its named components."""
    parts = _CPE_SPLIT.split(cpe.strip())
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    parts += ["*"] * (13 - len(parts))
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
        "update": parts[6],
    }


def _vcmp(a: str, b: str) -> int:
    return rpmvercmp(a, b)


def cpe_match_applies(match: Mapping[str, Any], cpe: Mapping[str, str], version: str) -> bool:
    """Whether one NVD ``cpeMatch`` criterion covers ``cpe`` at ``version``."""
    if not match.get("vulnerable", False):
        return False
    crit = parse_cpe(str(match.get("criteria", "")))
    if crit is None or (crit["vendor"], crit["product"]) != (cpe["vendor"], cpe["product"]):
        return False
    if crit["part"] not in ("*", cpe["part"]):
        return False
    bounds = {
        k: str(match[k])
        for k in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
        if isinstance(match.get(k), str)
    }
    if bounds:
        if (
            "versionStartIncluding" in bounds
            and _vcmp(version, bounds["versionStartIncluding"]) < 0
        ):
            return False
        if (
            "versionStartExcluding" in bounds
            and _vcmp(version, bounds["versionStartExcluding"]) <= 0
        ):
            return False
        if "versionEndIncluding" in bounds and _vcmp(version, bounds["versionEndIncluding"]) > 0:
            return False
        return not (
            "versionEndExcluding" in bounds and _vcmp(version, bounds["versionEndExcluding"]) >= 0
        )
    if crit["version"] in ("*", ""):
        return True
    if crit["version"] == "-" or _vcmp(version, crit["version"].replace("\\", "")) != 0:
        return False
    return crit["update"] in ("*", "-") or cpe["update"] in ("*", "-", crit["update"])


class NvdSource(VulnerabilitySource):
    """Upstream CPE matching against NVD (opt-in, low confidence)."""

    name = "nvd"

    def __init__(
        self,
        http: HttpClient,
        api_key: str | None = None,
        *,
        sleep: Callable[[float], None] | None = None,
        max_packages: int = 100,
    ) -> None:
        self.http = http
        self._api_key = api_key
        self._sleep = sleep
        self.max_packages = max_packages

    def __repr__(self) -> str:  # never expose the key
        return f"NvdSource(api_key={'set' if self._api_key else 'unset'})"

    @staticmethod
    def _cpe_targets(pkg: Package) -> list[tuple[dict[str, str], str]]:
        out = []
        for raw in pkg.cpes:
            cpe = parse_cpe(raw)
            if cpe is None or cpe["vendor"] in ("*", "") or cpe["product"] in ("*", ""):
                continue
            version = cpe["version"] if cpe["version"] not in ("*", "-", "") else pkg.version
            out.append((cpe, version.replace("\\", "")))
        return out

    def applicable(self, ctx: ScanContext, packages: list[Package]) -> list[Package]:
        return [p for p in packages if self._cpe_targets(p)]

    def match(self, ctx: ScanContext, packages: list[Package]) -> list[Vulnerability]:
        pkgs = sorted(self.applicable(ctx, packages), key=lambda p: p.id)
        if len(pkgs) > self.max_packages:
            ctx.limit(
                f"nvd: only the first {self.max_packages} of {len(pkgs)} CPE-identified"
                " packages were checked (rate limits)"
            )
            pkgs = pkgs[: self.max_packages]
        fragments: list[Fragment] = []
        for pkg in pkgs:
            seen: set[tuple[str, str, str]] = set()
            for cpe, version in self._cpe_targets(pkg):
                key = (cpe["vendor"], cpe["product"], version)
                if key in seen:
                    continue
                seen.add(key)
                for cve in self._fetch(cpe, version):
                    frag = self._fragment(pkg, cpe, version, cve)
                    if frag is not None:
                        fragments.append(frag)
        return merge_vulnerabilities(fragments)

    def _fetch(self, cpe: Mapping[str, str], version: str) -> list[dict[str, Any]]:
        headers = {"apiKey": self._api_key} if self._api_key else None
        delay = DELAY_WITH_KEY if self._api_key else DELAY_WITHOUT_KEY
        out: list[dict[str, Any]] = []
        start = 0
        for _ in range(MAX_PAGES):
            params = {
                "virtualMatchString": f"cpe:2.3:{cpe['part']}:{cpe['vendor']}:{cpe['product']}",
                "versionStart": version,
                "versionStartType": "including",
                "versionEnd": version,
                "versionEndType": "including",
                "resultsPerPage": str(RESULTS_PER_PAGE),
                "startIndex": str(start),
            }
            resp = self.http.get(NVD_URL, params=params, headers=headers, ttl=NVD_TTL)
            if not resp.from_cache:
                (self._sleep or time.sleep)(delay)
            try:
                doc = resp.json()
            except ValueError as exc:
                raise NetworkError("nvd: malformed response") from exc
            if not isinstance(doc, dict):
                raise NetworkError("nvd: unexpected response")
            items = doc.get("vulnerabilities") or []
            out.extend(
                i["cve"] for i in items if isinstance(i, dict) and isinstance(i.get("cve"), dict)
            )
            total = int(doc.get("totalResults") or 0)
            start += len(items)
            if not items or start >= total:
                break
        return out

    def _fragment(
        self, pkg: Package, cpe: Mapping[str, str], version: str, cve: Mapping[str, Any]
    ) -> Fragment | None:
        cve_id = cve.get("id")
        if not isinstance(cve_id, str):
            return None
        hits = [
            m
            for cfg in cve.get("configurations") or []
            for node in (cfg.get("nodes") or [] if isinstance(cfg, dict) else [])
            for m in (node.get("cpeMatch") or [] if isinstance(node, dict) else [])
            if isinstance(m, dict) and cpe_match_applies(m, cpe, version)
        ]
        if not hits:
            return None
        fixed = sorted(
            {
                str(m["versionEndExcluding"])
                for m in hits
                if isinstance(m.get("versionEndExcluding"), str)
            }
        )
        scores = []
        metrics = cve.get("metrics") or {}
        for key in _METRIC_KEYS:
            for metric in metrics.get(key) or [] if isinstance(metrics, dict) else []:
                data = metric.get("cvssData") if isinstance(metric, dict) else None
                if isinstance(data, dict) and isinstance(data.get("vectorString"), str):
                    kind = "CVSS_V2" if key.endswith("V2") else None
                    src = metric.get("source") if isinstance(metric.get("source"), str) else None
                    if parsed := parse_cvss(kind, data["vectorString"], src):
                        scores.append(parsed)
        cvss = sort_cvss(scores)
        cwes = [
            c
            for w in cve.get("weaknesses") or []
            for d in (w.get("description") or [] if isinstance(w, dict) else [])
            if isinstance(d, dict) and isinstance(d.get("value"), str)
            for c in [normalise_cwe(d["value"])]
            if c
        ]
        desc = next(
            (
                d.get("value")
                for d in cve.get("descriptions") or []
                if isinstance(d, dict) and d.get("lang") == "en"
            ),
            None,
        )
        refs = unique(
            str(r["url"])
            for r in cve.get("references") or []
            if isinstance(r, dict) and isinstance(r.get("url"), str)
        )[:MAX_REFERENCES]
        return Fragment(
            Vulnerability(
                id=cve_id,
                sources=["nvd"],
                package=pkg.id,
                package_name=pkg.name,
                installed_version=pkg.version,
                fixed_versions=fixed,
                status=VulnStatus.AFFECTED if fixed else VulnStatus.NO_FIX_AVAILABLE,
                summary=truncate(desc if isinstance(desc, str) else None),
                published=cve.get("published") if isinstance(cve.get("published"), str) else None,
                modified=cve.get("lastModified")
                if isinstance(cve.get("lastModified"), str)
                else None,
                severity=resolve_severity(cvss),
                cvss=cvss,
                cwes=sort_cwes(cwes),
                references=refs,
                match_confidence=Confidence.LOW,
                match_reason=(
                    f"nvd:cpe:2.3:{cpe['part']}:{cpe['vendor']}:{cpe['product']}"
                    f" version={version} (upstream CPE range; distro backports not considered)"
                ),
            )
        )
