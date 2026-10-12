"""Normalisation of advisory records into :class:`~startup_sbom.models.Vulnerability`.

Helpers here are source-agnostic: CVE identity extraction (``id`` / ``aliases`` /
``upstream`` / ``related``), CVSS parsing through the ``cvss`` library, severity
resolution (CVSS v4 > v3.1 > v3.0 > v2 > distro rating), CWE and reference
extraction, and the CVE-keyed merge that collapses duplicate findings (Debian
``DEBIAN-CVE-*`` + ``DSA-*``, OSV + NVD, ...) into one vulnerability per package.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from startup_sbom.models import (
    Confidence,
    CVSSScore,
    PackageType,
    Severity,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.vulns.versions import sort_versions

log = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_EMBEDDED_CVE_RE = re.compile(r"^[A-Z][A-Z0-9]*-(CVE-\d{4}-\d{4,})$")
_CWE_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)
_ADVISORY_PREFIXES = (
    "DSA-", "DLA-", "USN-", "RHSA-", "RHBA-", "RHEA-", "RLSA-", "RXSA-", "ALSA-", "ALBA-",
    "SUSE-", "openSUSE-", "ASA-", "AVG-", "ELSA-", "ALAS", "MGASA-", "OESA-",
)  # fmt: skip

MAX_REFERENCES = 10
MAX_SUMMARY = 300
_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
_CONF_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
_STATUS_RANK = {
    VulnStatus.AFFECTED: 6,
    VulnStatus.WILL_NOT_FIX: 5,
    VulnStatus.NO_FIX_AVAILABLE: 4,
    VulnStatus.UNDER_INVESTIGATION: 3,
    VulnStatus.NOT_AFFECTED: 2,
    VulnStatus.FIXED: 1,
}


# --------------------------------------------------------------------------- identity
def is_cve(identifier: str) -> bool:
    return bool(CVE_RE.match(identifier))


def embedded_cve(identifier: str) -> str | None:
    """``DEBIAN-CVE-2024-6119`` -> ``CVE-2024-6119`` (distro per-CVE record ids)."""
    m = _EMBEDDED_CVE_RE.match(identifier)
    return m.group(1) if m else None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def record_cves(record: Mapping[str, Any]) -> list[str]:
    """All CVE ids an OSV record refers to (sorted)."""
    rid = str(record.get("id", ""))
    own = rid if is_cve(rid) else embedded_cve(rid)
    if own:  # per-CVE record: anything else it lists is merely related
        return [own]
    found: set[str] = set()
    for key in ("aliases", "upstream"):
        for ident in _strings(record.get(key)):
            if is_cve(ident):
                found.add(ident)
            elif cve := embedded_cve(ident):
                found.add(cve)
    if not found:  # AlmaLinux / SUSE advisories list their CVEs only under "related"
        found = {i for i in _strings(record.get("related")) if is_cve(i)}
    return sorted(found)


def canonical_id(record: Mapping[str, Any]) -> str:
    """Stable id for a record that names no CVE (GHSA preferred, then lexical)."""
    rid = str(record.get("id", ""))
    ids = [rid, *_strings(record.get("aliases"))]
    return min(ids, key=lambda i: (not i.startswith("GHSA-"), i))


def is_advisory_id(identifier: str) -> bool:
    return identifier.startswith(_ADVISORY_PREFIXES)


# --------------------------------------------------------------------------- CVSS
def parse_cvss(kind: str | None, vector: str, source: str | None = None) -> CVSSScore | None:
    """Parse one CVSS vector (v2/v3.0/v3.1/v4.0).  Malformed vectors yield ``None``."""
    vector = vector.strip()
    try:
        if vector.startswith("CVSS:4.0/"):
            c4 = CVSS4(vector)
            return _score("4.0", c4.clean_vector(), float(c4.base_score), source)
        if vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            c3 = CVSS3(vector)
            return _score(vector[5:8], c3.clean_vector(), float(c3.base_score), source)
        if (kind or "").upper() == "CVSS_V2" or vector.startswith("AV:"):
            c2 = CVSS2(vector.removeprefix("(").removesuffix(")"))
            return _score("2.0", c2.clean_vector(), float(c2.base_score), source)
    except (CVSSError, ValueError, KeyError, IndexError, TypeError, ArithmeticError) as exc:
        log.debug("unparseable CVSS vector %r: %s", vector[:120], exc)
    return None


def _score(version: str, vector: str, base: float, source: str | None) -> CVSSScore:
    return CVSSScore(
        version=version,
        vector=vector,
        base_score=base,
        severity=Severity.from_score(base),
        source=source,
    )


def osv_severity_entries(
    record: Mapping[str, Any], entries: Iterable[Mapping[str, Any]] = ()
) -> list[Mapping[str, Any]]:
    """OSV ``severity`` objects at top level and on the given ``affected`` entries."""
    out: list[Mapping[str, Any]] = []
    for container in (record, *entries):
        sev = container.get("severity")
        if isinstance(sev, list):
            out.extend(s for s in sev if isinstance(s, Mapping))
    return out


def osv_cvss(
    record: Mapping[str, Any], entries: Iterable[Mapping[str, Any]] = ()
) -> list[CVSSScore]:
    """Parsed CVSS scores of an OSV record (deduplicated, best version first)."""
    scores: list[CVSSScore] = []
    for sev in osv_severity_entries(record, entries):
        kind, score = str(sev.get("type", "")), sev.get("score")
        if not kind.startswith("CVSS") or not isinstance(score, str):
            continue
        parsed = parse_cvss(kind, score, str(sev["source"]) if sev.get("source") else None)
        if parsed is not None:
            scores.append(parsed)
    return sort_cvss(scores)


def sort_cvss(scores: Iterable[CVSSScore]) -> list[CVSSScore]:
    seen: dict[tuple[str, str], CVSSScore] = {}
    for s in scores:
        seen.setdefault((s.version, s.vector), s)
    return sorted(
        seen.values(), key=lambda s: (_VERSION_RANK.get(s.version, 9), s.source or "", s.vector)
    )


_RATING_RE = re.compile(r"^(critical|important|high|moderate|medium|low)\s*:", re.IGNORECASE)


def osv_distro_severity(
    record: Mapping[str, Any], entries: Iterable[Mapping[str, Any]] = ()
) -> Severity:
    """Qualitative distro rating (Ubuntu priority, GHSA/RH severity, Debian urgency)."""
    entries = list(entries)
    candidates: list[str] = [
        s["score"]
        for s in osv_severity_entries(record, entries)
        if str(s.get("type", "")) == "Ubuntu" and isinstance(s.get("score"), str)
    ]
    for container in (record, *entries):
        for key in ("database_specific", "ecosystem_specific"):
            data = container.get(key)
            if isinstance(data, Mapping):
                candidates.extend(
                    data[f]
                    for f in ("severity", "urgency", "priority")
                    if isinstance(data.get(f), str)
                )
    summary = record.get("summary")
    if isinstance(summary, str) and (m := _RATING_RE.match(summary)):
        candidates.append(m.group(1))
    best = Severity.UNKNOWN
    for c in candidates:
        parsed = Severity.parse(c)
        if parsed.rank > best.rank:
            best = parsed
    return best


def resolve_severity(cvss: Iterable[CVSSScore], fallback: Severity = Severity.UNKNOWN) -> Severity:
    """Severity of the best CVSS version (v4 > v3.1 > v3.0 > v2), else ``fallback``."""
    for score in sort_cvss(cvss):
        if score.severity is not Severity.UNKNOWN:
            return score.severity
    return fallback


# --------------------------------------------------------------------------- other fields
def normalise_cwe(value: str) -> str | None:
    m = _CWE_RE.match(value.strip())
    return f"CWE-{int(m.group(1))}" if m else None


def sort_cwes(cwes: Iterable[str]) -> list[str]:
    return sorted(set(cwes), key=lambda c: int(c.split("-", 1)[1]))


def osv_cwes(record: Mapping[str, Any], entries: Iterable[Mapping[str, Any]] = ()) -> list[str]:
    out: set[str] = set()
    for container in (record, *entries):
        data = container.get("database_specific")
        if isinstance(data, Mapping):
            for raw in _strings(data.get("cwe_ids")) + _strings(data.get("cwes")):
                if cwe := normalise_cwe(raw):
                    out.add(cwe)
    return sort_cwes(out)


def osv_references(record: Mapping[str, Any]) -> list[str]:
    """Reference URLs, advisories first, capped at :data:`MAX_REFERENCES`."""
    refs = record.get("references")
    if not isinstance(refs, list):
        return []
    order = {"ADVISORY": 0, "FIX": 1, "REPORT": 2, "WEB": 3}
    items = [
        (order.get(str(r.get("type", "")), 4), idx, str(r["url"]))
        for idx, r in enumerate(refs)
        if isinstance(r, Mapping) and isinstance(r.get("url"), str)
    ]
    return unique([url for _, _, url in sorted(items)])[:MAX_REFERENCES]


def truncate(text: str | None, limit: int = MAX_SUMMARY) -> str | None:
    if not text:
        return None
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def osv_summary(record: Mapping[str, Any]) -> str | None:
    for key in ("summary", "details"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return truncate(value)
    return None


def unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


# --------------------------------------------------------------------------- merging
@dataclass(slots=True)
class Fragment:
    """One partial finding.  ``weight`` ranks how specific the source record is
    (2 = per-CVE record, 1 = advisory covering several CVEs)."""

    vuln: Vulnerability
    weight: int = 2


def merge_vulnerabilities(
    items: Iterable[Fragment | Vulnerability],
    ptypes: Mapping[str, PackageType] | None = None,
) -> list[Vulnerability]:
    """Collapse findings with the same ``(package, id)`` into one, deterministically."""
    groups: dict[tuple[str, str], list[Fragment]] = {}
    for item in items:
        frag = item if isinstance(item, Fragment) else Fragment(item)
        groups.setdefault((frag.vuln.package, frag.vuln.id), []).append(frag)
    out: list[Vulnerability] = []
    for (pkg, vid), frags in sorted(groups.items()):
        ptype = (ptypes or {}).get(pkg)
        out.append(_merge_group(vid, frags, ptype))
    return out


def _merge_group(vid: str, frags: list[Fragment], ptype: PackageType | None) -> Vulnerability:
    frags = sorted(
        frags,
        key=lambda f: (
            -f.weight,
            -_CONF_RANK[f.vuln.match_confidence],
            f.vuln.match_reason or "",
            ",".join(f.vuln.advisories),
        ),
    )
    first = frags[0].vuln
    vulns = [f.vuln for f in frags]
    top_conf = max(_CONF_RANK[v.match_confidence] for v in vulns)
    confident = [v for v in vulns if _CONF_RANK[v.match_confidence] == top_conf]

    fixed = unique(fv for v in vulns for fv in v.fixed_versions)
    fixed = sort_versions(ptype, fixed) if ptype is not None else sorted(fixed)
    status = max((v.status for v in confident), key=lambda s: _STATUS_RANK[s])
    if fixed and status in (VulnStatus.NO_FIX_AVAILABLE, VulnStatus.UNDER_INVESTIGATION):
        status = VulnStatus.AFFECTED

    cvss: list[CVSSScore] = []
    for weight in sorted({f.weight for f in frags}, reverse=True):
        cvss = sort_cvss(s for f in frags if f.weight == weight for s in f.vuln.cvss)
        if cvss:
            break
    fallback = max((v.severity for v in vulns), key=lambda s: s.rank)

    advisories = {a for v in vulns for a in v.advisories} - {vid}
    aliases = {a for v in vulns for a in v.aliases} - {vid} - advisories
    published = [v.published for v in vulns if v.published]
    modified = [v.modified for v in vulns if v.modified]
    reasons = unique(v.match_reason or "" for v in confident)
    return Vulnerability(
        id=vid,
        aliases=sorted(aliases),
        advisories=sorted(advisories),
        sources=sorted({s for v in vulns for s in v.sources}),
        package=first.package,
        package_name=first.package_name,
        installed_version=first.installed_version,
        fixed_versions=fixed,
        status=status,
        summary=next((v.summary for v in vulns if v.summary), None),
        published=min(published) if published else None,
        modified=max(modified) if modified else None,
        severity=resolve_severity(cvss, fallback),
        cvss=cvss,
        cwes=sort_cwes(c for v in vulns for c in v.cwes),
        epss=next((v.epss for v in vulns if v.epss is not None), None),
        epss_percentile=next(
            (v.epss_percentile for v in vulns if v.epss_percentile is not None), None
        ),
        kev=next((v.kev for v in vulns if v.kev is not None), None),
        references=unique(r for v in vulns for r in v.references)[:MAX_REFERENCES],
        match_confidence=next(c for c, r in _CONF_RANK.items() if r == top_conf),
        match_reason="; ".join(reasons[:3]) or None,
    )
