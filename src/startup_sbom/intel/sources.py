"""Structured per-CVE intel sources, all through the allow-listed :class:`HttpClient`.

Each function returns a :class:`Partial`; the orchestrator merges partials into an
:class:`~startup_sbom.models.IntelBundle` and isolates failures per source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from startup_sbom.errors import NetworkError
from startup_sbom.intel.extract import sanitize
from startup_sbom.intel.select import Reference
from startup_sbom.intel.store import article_id
from startup_sbom.models import IntelRecord, KEVInfo, OSInfo, PocRepo, VendorStatus
from startup_sbom.net import HttpClient, auth_headers
from startup_sbom.textsafe import safe
from startup_sbom.vulns.epss import EPSS_API_URL, _chunks

CVE_SERVICES_URL = "https://cveawg.mitre.org/api/cve/{cve}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_URL = "https://api.github.com/advisories"
UBUNTU_URL = "https://ubuntu.com/security/cves/{cve}.json"
REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
TTL = 24 * 3600.0
MAX_REFS = 200
MAX_TREND = 31
_RHEL_IDS = frozenset({"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn", "redhat"})
_URL = re.compile(r"https?://\S+")


@dataclass(slots=True, frozen=True)
class Signal:
    """Exploit evidence from a structured source (only these change exploitation)."""

    exploitation: str  # none | public_poc | active
    maturity: str  # none | poc | functional | weaponized
    source: str


@dataclass(slots=True)
class Partial:
    refs: list[Reference] = field(default_factory=list)
    advisories: list[IntelRecord] = field(default_factory=list)
    vendor: list[VendorStatus] = field(default_factory=list)
    cisa_ssvc: dict[str, str] = field(default_factory=dict)
    kev: KEVInfo | None = None
    poc_count: int | None = None
    poc_top: list[PocRepo] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def is_not_found(exc: Exception) -> bool:
    return isinstance(exc, NetworkError) and "HTTP 404" in str(exc)


def _json(http: HttpClient, url: str, *, ttl: float, **kw: Any) -> Any:
    resp = http.get(url, ttl=ttl, **kw)
    try:
        return resp.json()
    except ValueError as exc:
        raise NetworkError(f"malformed JSON from {url.split('/')[2]}") from exc


def _str(value: object, limit: int = 300) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sanitize(value, limit) or None


def _refs(items: object, origin: str) -> list[Reference]:
    out: list[Reference] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, str):
            out.extend(Reference(u, origin) for u in _URL.findall(item))
        elif isinstance(item, dict) and isinstance(item.get("url"), str):
            tags = item.get("tags")
            tag_t = tuple(sorted(str(t) for t in tags)) if isinstance(tags, list) else ()
            out.append(Reference(item["url"].strip(), origin, tag_t))
    return out[:MAX_REFS]


def structured_record(source: str, url: str, cve: str, now: datetime, **fields: Any) -> IntelRecord:
    return IntelRecord(
        id=article_id(url),
        source=source,
        url=url,
        kind=fields.pop("kind", "advisory"),
        cves=[cve],
        fetched_at=now,
        trust="structured",
        **fields,
    )


# --------------------------------------------------------------------------- CVE Services
def normalise_ssvc(options: object) -> dict[str, str]:
    """CISA Vulnrichment SSVC options -> dict; ``Exploitation: poc`` -> ``public_poc``."""
    out: dict[str, str] = {}
    for opt in options if isinstance(options, list) else []:
        if not isinstance(opt, dict):
            continue
        for key, value in opt.items():
            if isinstance(key, str) and isinstance(value, str):
                v = value.strip().lower()
                if key.strip().lower() == "exploitation" and v == "poc":
                    v = "public_poc"
                out[safe(key.strip(), 40)] = safe(v, 40)
    return dict(sorted(out.items()))


def parse_cve_record(doc: Any, cve: str, now: datetime) -> Partial:
    if not isinstance(doc, dict) or not isinstance(doc.get("containers"), dict):
        raise NetworkError("cve.org: unexpected record format")
    part = Partial()
    containers = doc["containers"]
    cna = _dict(containers.get("cna"))
    part.refs += _refs(cna.get("references"), "cna")
    for adp in containers.get("adp") or []:
        if not isinstance(adp, dict):
            continue
        meta = _dict(adp.get("providerMetadata"))
        short = str(meta.get("shortName") or "")
        part.refs += _refs(adp.get("references"), "cisa-adp" if short == "CISA-ADP" else "cve-adp")
        if short != "CISA-ADP":
            continue
        for metric in adp.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or not isinstance(other.get("content"), dict):
                continue
            content = other["content"]
            if other.get("type") == "ssvc":
                part.cisa_ssvc = normalise_ssvc(content.get("options"))
                exp = part.cisa_ssvc.get("Exploitation")
                if exp == "active":
                    part.signals.append(Signal("active", "functional", "cisa-ssvc"))
                elif exp == "public_poc":
                    part.signals.append(Signal("public_poc", "poc", "cisa-ssvc"))
            elif other.get("type") == "kev":
                part.kev = KEVInfo(date_added=_str(content.get("dateAdded"), 20))
                part.signals.append(Signal("active", "functional", "cisa-kev"))
    meta = _dict(doc.get("cveMetadata"))
    desc = next(
        (
            d.get("value")
            for d in cna.get("descriptions") or []
            if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")
        ),
        None,
    )
    state = str(meta.get("state") or "")
    title = _str(cna.get("title")) or (f"{cve} ({state.lower()})" if state == "REJECTED" else None)
    part.advisories.append(
        structured_record(
            "cve.org",
            f"https://www.cve.org/CVERecord?id={cve}",
            cve,
            now,
            title=title,
            site="cve.org",
            published=_str(meta.get("datePublished"), 40),
            snippet=_str(desc, 600),
        )
    )
    return part


def cve_services(http: HttpClient, cve: str, *, ttl: float, now: datetime) -> Partial:
    return parse_cve_record(_json(http, CVE_SERVICES_URL.format(cve=cve), ttl=ttl), cve, now)


# --------------------------------------------------------------------------- NVD
def parse_nvd(doc: Any, cve: str) -> Partial:
    part = Partial()
    vulns = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(vulns, list) or not vulns or not isinstance(vulns[0], dict):
        return part
    item = _dict(vulns[0].get("cve"))
    part.refs = _refs(item.get("references"), "nvd")
    if any("Exploit" in r.tags for r in part.refs):
        part.signals.append(Signal("public_poc", "poc", "nvd-exploit-tag"))
    if _str(item.get("cisaExploitAdd")):
        part.kev = KEVInfo(
            date_added=_str(item.get("cisaExploitAdd"), 20),
            due_date=_str(item.get("cisaActionDue"), 20),
            required_action=_str(item.get("cisaRequiredAction"), 300),
        )
        part.signals.append(Signal("active", "functional", "cisa-kev"))
    return part


def nvd(http: HttpClient, cve: str, *, ttl: float, api_key: str | None = None) -> Partial:
    headers = {"apiKey": api_key} if api_key else auth_headers(NVD_URL) or None
    return parse_nvd(_json(http, NVD_URL, ttl=ttl, params={"cveId": cve}, headers=headers), cve)


# --------------------------------------------------------------------------- GHSA
def ghsa(http: HttpClient, cve: str, *, ttl: float, now: datetime) -> Partial:
    """GitHub advisories (call only when a token is configured)."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    headers.update(auth_headers(GHSA_URL))
    doc = _json(http, GHSA_URL, ttl=ttl, params={"cve_id": cve}, headers=headers)
    part = Partial()
    for adv in doc if isinstance(doc, list) else []:
        if not isinstance(adv, dict):
            continue
        url = adv.get("html_url")
        gid = _str(adv.get("ghsa_id"), 40)
        if not isinstance(url, str) or not url.startswith("https://github.com/advisories/"):
            continue
        summary = _str(adv.get("summary"), 250)
        part.advisories.append(
            structured_record(
                "ghsa",
                url,
                cve,
                now,
                title=f"{gid}: {summary}" if gid and summary else gid or summary,
                site="GitHub Advisory Database",
                published=_str(adv.get("published_at"), 40),
                snippet=_str(adv.get("description"), 600),
            )
        )
        part.refs += _refs(adv.get("references"), "ghsa")
    return part


# --------------------------------------------------------------------------- vendors
def _ids(os_info: OSInfo | None) -> set[str]:
    if os_info is None:
        return set()
    return {os_info.id.lower(), *(i.lower() for i in os_info.id_like)}


def ubuntu_relevant(os_info: OSInfo | None) -> bool:
    ids = _ids(os_info)
    return not ids or "unknown" in ids or bool(ids & {"ubuntu", "debian"})


def redhat_relevant(os_info: OSInfo | None) -> bool:
    ids = _ids(os_info)
    family = (os_info.family or "") if os_info else ""
    return not ids or "unknown" in ids or family == "rhel" or bool(ids & _RHEL_IDS)


def parse_ubuntu(doc: Any, cve: str, os_info: OSInfo | None) -> Partial:
    if not isinstance(doc, dict):
        raise NetworkError("ubuntu: unexpected format")
    status = None
    codename = (os_info.version_codename or "").lower() if os_info else ""
    if codename and os_info is not None and os_info.id == "ubuntu":
        found: list[str] = []
        for pkg in doc.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            for st in pkg.get("statuses") or []:
                if isinstance(st, dict) and str(st.get("release_codename")).lower() == codename:
                    detail = _str(st.get("description"), 60)
                    found.append(
                        f"{safe(pkg.get('name'), 60)}: {safe(st.get('status'), 30)}"
                        + (f" ({detail})" if detail else "")
                    )
        status = "; ".join(sorted(found)[:5]) or None
    notes = [n.get("note") for n in doc.get("notes") or [] if isinstance(n, dict)]
    notices = doc.get("notices_ids")
    vendor = VendorStatus(
        vendor="ubuntu",
        severity=_str(doc.get("priority"), 30),
        status=status,
        statement=_str(doc.get("ubuntu_description"), 600) or _str(next(iter(notes), None), 600),
        mitigation=_str(doc.get("mitigation"), 600),
        advisories=sorted({safe(n, 40) for n in notices if isinstance(n, str)})[:20]
        if isinstance(notices, list)
        else [],
        url=f"https://ubuntu.com/security/{cve}",
    )
    return Partial(vendor=[vendor], refs=_refs(doc.get("references"), "ubuntu"))


def parse_redhat(doc: Any, cve: str, os_info: OSInfo | None) -> Partial:
    if not isinstance(doc, dict):
        raise NetworkError("redhat: unexpected format")
    releases = [r for r in doc.get("affected_release") or [] if isinstance(r, dict)]
    states = [s for s in doc.get("package_state") or [] if isinstance(s, dict)]
    status = None
    major = ((os_info.version_id or "").split(".")[0]) if os_info else ""
    if major and redhat_relevant(os_info) and _ids(os_info):
        product = f"Red Hat Enterprise Linux {major}"
        fixed = sorted(
            f"fixed in {safe(r.get('advisory'), 30)}"
            for r in releases
            if str(r.get("product_name", "")).startswith(product) and r.get("advisory")
        )
        open_states = sorted(
            f"{safe(s.get('package_name'), 60)}: {safe(s.get('fix_state'), 30)}"
            for s in states
            if str(s.get("product_name", "")).startswith(product)
        )
        status = "; ".join((fixed or open_states)[:5]) or None
    mitigation = doc.get("mitigation")
    if isinstance(mitigation, dict):
        mitigation = mitigation.get("value")
    vendor = VendorStatus(
        vendor="redhat",
        severity=_str(doc.get("threat_severity"), 30),
        status=status,
        statement=_str(doc.get("statement"), 600),
        mitigation=_str(mitigation, 600),
        advisories=sorted({safe(r["advisory"], 40) for r in releases if r.get("advisory")})[:20],
        url=f"https://access.redhat.com/security/cve/{cve}",
    )
    return Partial(vendor=[vendor], refs=_refs(doc.get("references"), "redhat"))


def ubuntu(http: HttpClient, cve: str, *, ttl: float, os_info: OSInfo | None = None) -> Partial:
    try:
        doc = _json(http, UBUNTU_URL.format(cve=cve), ttl=ttl)
    except NetworkError as exc:
        if is_not_found(exc):
            return Partial()
        raise
    return parse_ubuntu(doc, cve, os_info)


def redhat(http: HttpClient, cve: str, *, ttl: float, os_info: OSInfo | None = None) -> Partial:
    try:
        doc = _json(http, REDHAT_URL.format(cve=cve), ttl=ttl)
    except NetworkError as exc:
        if is_not_found(exc):
            return Partial()
        raise
    return parse_redhat(doc, cve, os_info)


# --------------------------------------------------------------------------- PoC-in-GitHub
def parse_poc_repos(doc: Any) -> Partial:
    """Metadata only: PoC repositories are never cloned, downloaded or rendered."""
    repos = [
        r
        for r in (doc if isinstance(doc, list) else [])
        if isinstance(r, dict) and not r.get("fork") and isinstance(r.get("full_name"), str)
    ]

    def stars(r: dict[str, Any]) -> int:
        try:
            return int(r.get("stargazers_count") or 0)
        except (TypeError, ValueError):
            return 0

    repos.sort(key=lambda r: (-stars(r), str(r["full_name"])))
    top = []
    for r in repos[:5]:
        name = safe(r["full_name"], 120)
        url = r.get("html_url")
        if not isinstance(url, str) or not url.startswith("https://github.com/"):
            url = f"https://github.com/{name}"
        top.append(
            PocRepo(
                full_name=name,
                url=safe(url, 300),
                description=_str(r.get("description"), 200),
                stars=stars(r),
                created_at=_str(r.get("created_at"), 40),
                pushed_at=_str(r.get("pushed_at"), 40),
            )
        )
    part = Partial(poc_count=len(repos), poc_top=top)
    if repos:
        part.signals.append(Signal("public_poc", "poc", "poc-in-github"))
    return part


def poc_in_github(http: HttpClient, cve: str, *, ttl: float) -> Partial:
    url = POC_URL.format(year=cve.split("-")[1], cve=cve)
    try:
        doc = _json(http, url, ttl=ttl)
    except NetworkError as exc:
        if is_not_found(exc):
            return Partial(poc_count=0)
        raise
    return parse_poc_repos(doc)


# --------------------------------------------------------------------------- EPSS trend
def parse_epss_trends(doc: Any) -> dict[str, list[tuple[str, float]]]:
    out: dict[str, list[tuple[str, float]]] = {}
    rows = doc.get("data") if isinstance(doc, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("cve"), str):
            continue
        points: set[tuple[str, float]] = set()
        for item in [row, *(row.get("time-series") or [])]:
            if not isinstance(item, dict):
                continue
            try:
                points.add((str(item["date"])[:10], round(float(item["epss"]), 6)))
            except (KeyError, TypeError, ValueError):
                continue
        by_date = dict(sorted(points))
        out[row["cve"]] = sorted(by_date.items())[-MAX_TREND:]
    return out


def epss_trends(
    http: HttpClient, cves: list[str], *, ttl: float = TTL
) -> dict[str, list[tuple[str, float]]]:
    """30-day EPSS time series, batched (reuses the EPSS client's safe chunking)."""
    out: dict[str, list[tuple[str, float]]] = {}
    for chunk in _chunks(sorted(set(cves))):
        params = {"cve": ",".join(chunk), "scope": "time-series", "limit": str(len(chunk))}
        out.update(parse_epss_trends(_json(http, EPSS_API_URL, ttl=ttl, params=params)))
    return out
