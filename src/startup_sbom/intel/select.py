"""CVE prioritisation and reference ranking (which articles are worth fetching)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from startup_sbom.models import Report, SSVCDecision, Vulnerability

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

_DECISION_RANK = {
    SSVCDecision.ACT: 3,
    SSVCDecision.ATTEND: 2,
    SSVCDecision.TRACK_STAR: 1,
    SSVCDecision.TRACK: 0,
}

# Hosts already consumed in structured form, code hosts (PoC repos are never fetched),
# social media, gated sites and search engines.
SKIP_HOSTS = frozenset(
    {
        "nvd.nist.gov", "www.cve.org", "cve.org", "cve.mitre.org", "cveawg.mitre.org",
        "github.com", "gist.github.com", "api.github.com", "raw.githubusercontent.com",
        "gitlab.com", "bitbucket.org", "ubuntu.com", "access.redhat.com",
        "bugzilla.redhat.com", "security-tracker.debian.org", "www.cisa.gov",
        "www.exploit-db.com", "exploit-db.com", "packetstormsecurity.com",
        "packetstorm.news", "packetstormsecurity.org", "lists.fedoraproject.org",
        "x.com", "twitter.com", "mobile.twitter.com", "www.facebook.com",
        "www.linkedin.com", "t.me", "www.youtube.com", "youtube.com", "youtu.be",
        "news.ycombinator.com", "www.reddit.com", "reddit.com", "www.google.com",
        "google.com", "www.bing.com", "duckduckgo.com", "search.yahoo.com",
    }
)  # fmt: skip
SKIP_SUFFIXES = (".exploit-db.com", ".packetstormsecurity.com", ".reddit.com")
SKIP_EXTENSIONS = (
    ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".rar", ".exe", ".msi", ".bin", ".deb",
    ".rpm", ".apk", ".jar", ".iso", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".pdf",
    ".dmg", ".so", ".dll", ".py", ".c", ".sh", ".rb", ".patch", ".diff",
)  # fmt: skip
TAG_WEIGHT = {
    "Exploit": 5,
    "Technical Description": 4,
    "Third Party Advisory": 3,
    "Vendor Advisory": 3,
    "Patch": 2,
    "Press/Media Coverage": 2,
    "Mitigation": 2,
    "Release Notes": 1,
    "Mailing List": 1,
}
KIND_BY_TAG = (
    ("Exploit", "exploit"),
    ("Patch", "patch"),
    ("Vendor Advisory", "vendor"),
    ("Mitigation", "vendor"),
    ("Third Party Advisory", "writeup"),
    ("Mailing List", "mailing-list"),
)
_TRUSTED_ORIGINS = frozenset({"cna", "ubuntu", "redhat", "nvd"})
MAX_PER_HOST = 2


@dataclass(slots=True, frozen=True)
class Reference:
    """A reference URL with whatever typing the source provided."""

    url: str
    origin: str  # cna | cisa-adp | cve-adp | nvd | osv | ubuntu | redhat | ghsa | search:<p>
    tags: tuple[str, ...] = ()


@dataclass(slots=True)
class Candidate:
    url: str
    kind: str
    score: float
    origins: list[str] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class Target:
    """One CVE selected for prefetch, with the report context that ranked it."""

    cve: str
    vulnerabilities: tuple[Vulnerability, ...]
    key: tuple[float, ...]


# --------------------------------------------------------------------------- CVEs
def _cve_of(vuln: Vulnerability) -> str | None:
    if CVE_RE.match(vuln.id):
        return vuln.id
    return next((a for a in sorted(vuln.aliases) if CVE_RE.match(a)), None)


def select_cves(report: Report, limit: int) -> tuple[list[Target], list[str]]:
    """Top ``limit`` CVEs (SSVC Act > Attend > Track* > Track, KEV, risk, EPSS) + leftovers."""
    vulns_by_id: dict[str, list[Vulnerability]] = {}
    for vuln in report.vulnerabilities:
        vulns_by_id.setdefault(vuln.id, []).append(vuln)
    best: dict[str, tuple[float, ...]] = {}
    ctx: dict[str, list[Vulnerability]] = {}

    def consider(cve: str, key: tuple[float, ...], vulns: Iterable[Vulnerability]) -> None:
        if cve not in best or key > best[cve]:
            best[cve] = key
        bucket = ctx.setdefault(cve, [])
        bucket.extend(v for v in vulns if v not in bucket)

    for threat in report.threats:
        vulns = vulns_by_id.get(threat.vulnerability, [])
        cve = next((c for c in (_cve_of(v) for v in vulns) if c), None)
        if cve is None and CVE_RE.match(threat.vulnerability):
            cve = threat.vulnerability
        if cve is None:
            continue
        decision = _DECISION_RANK.get(threat.ssvc.decision, -1) if threat.ssvc else -1
        kev = any(v.kev is not None for v in vulns)
        epss = max((v.epss or 0.0 for v in vulns), default=0.0)
        consider(cve, (float(decision), float(kev), threat.risk_score, epss), vulns)
    if not report.threats:  # threat stage disabled: rank the raw findings
        for vuln in report.vulnerabilities:
            cve = _cve_of(vuln)
            if cve is not None:
                key = (-1.0, float(vuln.kev is not None), float(vuln.severity.rank), vuln.epss or 0)
                consider(cve, key, [vuln])
    ordered = sorted(best, key=lambda c: (tuple(-x for x in best[c]), c))
    chosen = [
        Target(cve=c, vulnerabilities=tuple(ctx.get(c, [])), key=best[c])
        for c in ordered[: max(0, limit)]
    ]
    return chosen, ordered[max(0, limit) :]


# --------------------------------------------------------------------------- articles
def normalise_url(url: str) -> str | None:
    """https twin of a http(s) URL without fragment or trailing slash; None if unusable."""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.hostname:
        return None
    path = parts.path.rstrip("/") or ""
    return urlunsplit(("https", parts.netloc.lower(), path, parts.query, ""))


def _skip(url: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in SKIP_HOSTS or host.endswith(SKIP_SUFFIXES) or host.endswith(".github.com"):
        return True
    return parts.path.lower().endswith(SKIP_EXTENSIONS)


def _kind(url: str, tags: Iterable[str]) -> str:
    tag_set = set(tags)
    for tag, kind in KIND_BY_TAG:
        if tag in tag_set:
            return kind
    lowered = url.lower()
    if "/lists/" in lowered or "seclists.org" in lowered or "lists." in lowered:
        return "mailing-list"
    return "writeup"


def rank_references(refs: Iterable[Reference], limit: int) -> list[Candidate]:
    """Rank references into at most ``limit`` article candidates (<= 2 per host)."""
    merged: dict[str, Candidate] = {}
    for ref in refs:
        if "Broken Link" in ref.tags:
            continue
        url = normalise_url(ref.url)
        if url is None or _skip(url):
            continue
        score = 1.0 + sum(TAG_WEIGHT.get(t, 0) for t in ref.tags)
        if ref.origin in _TRUSTED_ORIGINS:
            score += 1
        kind = _kind(url, ref.tags)
        prev = merged.get(url)
        if prev is None:
            merged[url] = Candidate(url=url, kind=kind, score=score, origins=[ref.origin])
            continue
        hi, lo = max(prev.score, score), min(prev.score, score)
        if score > prev.score:
            prev.kind = kind
        prev.score = hi + 0.5 * lo
        if ref.origin not in prev.origins:
            prev.origins.append(ref.origin)
    ranked = sorted(merged.values(), key=lambda c: (-c.score, c.url))
    per_host: dict[str, int] = {}
    out: list[Candidate] = []
    for cand in ranked:
        if len(out) >= limit:
            break
        host = urlsplit(cand.url).hostname or ""
        if per_host.get(host, 0) >= MAX_PER_HOST:
            continue
        per_host[host] = per_host.get(host, 0) + 1
        cand.origins.sort()
        out.append(cand)
    return out
