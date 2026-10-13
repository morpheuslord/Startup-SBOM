"""OSV.dev matching: distro-aware, by source package, exact ecosystem and full version.

Rules (each verified against the live API, see ``Docs/Refactor Plan.md`` C-5):

* Distro records are indexed by **source** package (Debian, Ubuntu, Alpine, Rocky,
  SUSE, ...): query ``Package.source_name`` with the source version.  Red Hat and
  AlmaLinux list **binary** names, so RPM packages are queried by both names.
* The version is sent exactly as the distro writes it, epoch included.
* Ecosystem strings come verbatim from ``OSInfo.vuln_ecosystems``.  Red Hat and SLES
  publish per-repository / per-module streams that cannot be recovered from the
  package database, so those are queried by base ecosystem (``Red Hat``, ``SUSE``)
  and the ``affected`` entries are filtered and re-evaluated locally.
* ``/v1/querybatch`` (<= 1000 queries, paginated per query) returns ids only; full
  records are hydrated with ``/v1/vulns/{id}`` and cached by ``(id, modified)``.
* Offline, query results and records are served from the cache only.
* Rolling Debian derivatives OSV does not cover (Kali, ...) are queried against
  Debian testing (:func:`startup_sbom.distro.derivative_fallback_ecosystem`) with
  the vendor's revision suffix removed; those matches get reduced confidence.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any
from urllib.parse import quote

from packageurl import PackageURL

from startup_sbom.context import ScanContext
from startup_sbom.distro import derivative_fallback_ecosystem
from startup_sbom.errors import NetworkError
from startup_sbom.models import (
    Confidence,
    OSInfo,
    Package,
    PackageType,
    Vulnerability,
    VulnStatus,
)
from startup_sbom.net import HttpClient
from startup_sbom.vulns.base import VulnerabilitySource
from startup_sbom.vulns.normalize import (
    Fragment,
    canonical_id,
    is_advisory_id,
    is_cve,
    merge_vulnerabilities,
    osv_cvss,
    osv_cwes,
    osv_distro_severity,
    osv_references,
    osv_summary,
    record_cves,
)
from startup_sbom.vulns.versions import (
    compare,
    ecosystem_package_type,
    sort_versions,
    strip_derivative_suffix,
)

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev"
QUERYBATCH_URL = f"{OSV_API}/v1/querybatch"
QUERYBATCH_MAX = 1000
MAX_PAGES = 50
QUERY_TTL = 6 * 3600.0
VULN_TTL = 30 * 86400.0  # records are immutable for a given ``modified`` stamp

OS_TYPES = frozenset({PackageType.DEB, PackageType.RPM, PackageType.APK})
LANGUAGE_ECOSYSTEMS: dict[PackageType, str] = {
    PackageType.PYPI: "PyPI",
    PackageType.NPM: "npm",
    PackageType.GOLANG: "Go",
    PackageType.MAVEN: "Maven",
    PackageType.CARGO: "crates.io",
}
STREAM_BASES = frozenset({"Red Hat", "SUSE"})
_RHEL_RE = re.compile(r"^Red Hat:enterprise_linux:(\d+)(?:\.(\d+))?(?=$|:)")
_SUSE_TOKEN_RE = re.compile(r"(\d+(?:\.\d+)?(?: SP\d+)?)(?:-[A-Za-z]+)?$")
_WILL_NOT_FIX = frozenset({"end-of-life", "ignored", "will_not_fix", "will not fix", "wontfix"})
_NOT_AFFECTED = frozenset({"not-affected", "not_affected", "dne"})
_INVESTIGATING = frozenset({"needs-triage", "under_investigation", "undetermined"})
_CONF_ORDER = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


# --------------------------------------------------------------------------- ecosystems
def _strip_wildcard(eco: str) -> str:
    return eco.rstrip("*").rstrip(":")


def _is_suse_enterprise(eco: str) -> bool:
    return eco.startswith("SUSE:") and "Linux Enterprise" in eco


def is_stream_ecosystem(requested: str) -> bool:
    """Whether ``requested`` must be queried by base ecosystem and filtered locally."""
    req = _strip_wildcard(requested)
    return req in STREAM_BASES or req.startswith("Red Hat:") or _is_suse_enterprise(req)


def query_ecosystem(requested: str) -> str:
    """The ecosystem string actually sent to OSV for ``requested``."""
    req = _strip_wildcard(requested)
    if is_stream_ecosystem(requested):
        return req.split(":", 1)[0]
    return req


def ecosystem_matches(requested: str, actual: str) -> bool:
    """Whether an ``affected[].package.ecosystem`` value belongs to ``requested``."""
    req = _strip_wildcard(requested)
    if actual in (requested, req):
        return True
    if requested.endswith("*"):
        return actual.startswith(requested.rstrip("*"))
    if m := _RHEL_RE.match(req):
        am = _RHEL_RE.match(actual)
        if am is None or am.group(1) != m.group(1):
            return False
        # a major-level request accepts every stream of that major; a minor-level one
        # (RHEL 10.x) accepts its own minor plus the major-wide streams
        return m.group(2) is None or am.group(2) is None or am.group(2) == m.group(2)
    if req in STREAM_BASES:  # unversioned: every stream of the vendor (approximate)
        return actual.startswith(req + ":")
    if _is_suse_enterprise(req) and _is_suse_enterprise(actual):
        tm = _SUSE_TOKEN_RE.search(req)
        if tm is None:
            return False
        pattern = rf"(?<![\d.]){re.escape(tm.group(1))}(?![\d.]|\sSP)"
        return re.search(pattern, actual.split(":", 1)[1]) is not None
    return False


def _norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


# --------------------------------------------------------------------------- local range evaluation
def _event_value(event: Mapping[str, Any]) -> tuple[str, str] | None:
    for key in ("introduced", "fixed", "last_affected", "limit"):
        value = event.get(key)
        if isinstance(value, str):
            return key, value
    return None


def entry_affects(entry: Mapping[str, Any], version: str, ptype: PackageType) -> tuple[bool, bool]:
    """Evaluate an OSV ``affected`` entry locally.

    Returns ``(affected, epoch_ignored)``; the second flag is set when the vendor's
    events carry no epoch while the installed RPM has one, so the epoch was dropped
    for the comparison (openEuler / Azure Linux style records).
    """
    versions = entry.get("versions")
    if isinstance(versions, list) and version in versions:
        return True, False
    affected = False
    epoch_ignored = False
    for rng in entry.get("ranges") or []:
        if not isinstance(rng, Mapping) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        events = [ev for ev in (_event_value(e) for e in rng.get("events") or []) if ev]
        installed = version
        if ptype in (PackageType.RPM, PackageType.ALPM) and ":" in version:
            epoch, _, rest = version.partition(":")
            if epoch.isdigit() and int(epoch) > 0 and not any(":" in v for _, v in events):
                installed = rest
                epoch_ignored = True

        def order(x: tuple[str, str], y: tuple[str, str]) -> int:
            if x[1] == "0" or y[1] == "0":
                return (y[1] == "0") - (x[1] == "0")
            return compare(ptype, x[1], y[1])

        status = False
        for kind, value in sorted(events, key=cmp_to_key(order)):
            if kind == "introduced" and (value == "0" or compare(ptype, installed, value) >= 0):
                status = True
            elif (kind == "fixed" and compare(ptype, installed, value) >= 0) or (
                kind == "last_affected" and compare(ptype, installed, value) > 0
            ):
                status = False
        affected = affected or status
    return affected, epoch_ignored and affected


def fixed_versions(
    entries: Iterable[Mapping[str, Any]], version: str, ptype: PackageType
) -> list[str]:
    """``fixed`` events newer than ``version`` (all of them if none compares newer)."""
    found = {
        str(ev["fixed"])
        for entry in entries
        for rng in entry.get("ranges") or []
        if isinstance(rng, Mapping) and rng.get("type") in ("ECOSYSTEM", "SEMVER")
        for ev in rng.get("events") or []
        if isinstance(ev, Mapping) and isinstance(ev.get("fixed"), str)
    }
    raw = sort_versions(ptype, list(found))
    newer = [f for f in raw if compare(ptype, version, f) < 0]
    if not newer and raw and ptype in (PackageType.RPM, PackageType.ALPM) and ":" in version:
        bare = version.partition(":")[2]
        newer = [f for f in raw if ":" not in f and compare(ptype, bare, f) < 0]
    return newer or raw


def distro_status(entries: Iterable[Mapping[str, Any]]) -> VulnStatus | None:
    """Explicit distro decision recorded on the entries (Debian urgency, status fields)."""
    found: set[VulnStatus] = set()
    for entry in entries:
        for key in ("ecosystem_specific", "database_specific"):
            data = entry.get(key)
            if not isinstance(data, Mapping):
                continue
            for field in ("urgency", "status", "state"):
                value = data.get(field)
                if not isinstance(value, str):
                    continue
                v = value.strip().lower()
                if v in _WILL_NOT_FIX:
                    found.add(VulnStatus.WILL_NOT_FIX)
                elif v in _NOT_AFFECTED:
                    found.add(VulnStatus.NOT_AFFECTED)
                elif v in _INVESTIGATING:
                    found.add(VulnStatus.UNDER_INVESTIGATION)
    for status in (
        VulnStatus.WILL_NOT_FIX,
        VulnStatus.UNDER_INVESTIGATION,
        VulnStatus.NOT_AFFECTED,
    ):
        if status in found:
            return status
    return None


# --------------------------------------------------------------------------- planning
@dataclass(frozen=True, slots=True, order=True)
class OsvQuery:
    """One ``/v1/querybatch`` query."""

    ecosystem: str
    name: str
    version: str

    @property
    def cache_key(self) -> str:
        return f"{self.ecosystem}\x00{self.name}\x00{self.version}"

    def payload(self, page_token: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "package": {"name": self.name, "ecosystem": self.ecosystem},
            "version": self.version,
        }
        if page_token:
            body["page_token"] = page_token
        return body


@dataclass(frozen=True, slots=True)
class QueryTarget:
    """A package a query speaks for, and the ecosystem the user's OS asked for."""

    package: Package
    requested: str
    kind: str  # source | binary | package
    derived_from: str | None = None  # installed version, when a derivative suffix was cut
    fallback: bool = False  # ``requested`` is a derivative-fallback (parent) ecosystem


def _strip_zero_epoch(v: str) -> str:
    return v[2:] if v.startswith("0:") else v


def full_version(pkg: Package) -> str:
    """Installed version with epoch exactly as the distro writes it (``0:`` dropped)."""
    v = _strip_zero_epoch(pkg.version.strip())
    native = pkg.type in (PackageType.DEB, PackageType.RPM, PackageType.ALPM)
    if native and pkg.epoch and ":" not in v:
        v = f"{pkg.epoch}:{v}"
    return v


def source_version(pkg: Package) -> str:
    """Version to send with the source-name query."""
    if not pkg.source_version:
        return full_version(pkg)
    sv = _strip_zero_epoch(pkg.source_version.strip())
    if pkg.type == PackageType.RPM and ":" not in sv:
        # SOURCERPM carries no epoch; the binary header does
        head, sep, _ = full_version(pkg).partition(":")
        if sep and head.isdigit():
            sv = f"{head}:{sv}"
    return sv


def _purl(pkg: Package) -> PackageURL | None:
    if not pkg.purl:
        return None
    try:
        return PackageURL.from_string(pkg.purl)
    except ValueError:
        return None


def language_name(pkg: Package) -> str:
    """OSV package name of a language package."""
    purl = _purl(pkg)
    if pkg.type == PackageType.PYPI:
        return _norm_name("PyPI", pkg.name)
    if pkg.type == PackageType.MAVEN:
        if ":" in pkg.name:
            return pkg.name
        if purl is not None and purl.namespace:
            return f"{purl.namespace}:{purl.name}"
        return pkg.name
    if (
        pkg.type in (PackageType.NPM, PackageType.GOLANG)
        and "/" not in pkg.name
        and purl is not None
        and purl.namespace
    ):
        return f"{purl.namespace}/{purl.name}"
    return pkg.name


def language_version(pkg: Package) -> str:
    v = pkg.version.strip()
    if pkg.type == PackageType.GOLANG and v[:1] == "v" and v[1:2].isdigit():
        v = v[1:]
    return v


_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?")


def refine_ecosystem(os: OSInfo, eco: str) -> str:
    """Narrow a bare vendor ecosystem (``Red Hat``, ``SUSE``) to the installed release.

    ``Red Hat`` + ``VERSION_ID=9.4`` -> ``Red Hat:enterprise_linux:9`` (RHEL 10+ streams
    are per minor: ``10.1``); ``SUSE`` + ``PRETTY_NAME="SUSE Linux Enterprise Server 15
    SP6"`` -> ``SUSE:Linux Enterprise Server 15 SP6``.  Unknown releases stay bare.
    """
    m = _VERSION_RE.match(os.version_id or "")
    if eco == "Red Hat" and m:
        major, minor = m.group(1), m.group(2)
        if int(major) >= 10 and minor is not None:
            return f"Red Hat:enterprise_linux:{major}.{minor}"
        return f"Red Hat:enterprise_linux:{major}"
    if eco == "SUSE":
        pretty = (os.pretty_name or "").strip()
        if pretty.startswith("SUSE ") and _SUSE_TOKEN_RE.search(pretty):
            return "SUSE:" + pretty.removeprefix("SUSE ")
        if m and os.id in ("sles", "sles_sap"):
            major, minor = m.group(1), m.group(2) or "0"
            token = (
                f"{major}.{minor}"
                if int(major) >= 16
                else (f"{major} SP{minor}" if minor != "0" else major)
            )
            return f"SUSE:Linux Enterprise Server {token}"
    return eco


def fallback_ecosystem(ctx: ScanContext) -> str | None:
    """The derivative-fallback ecosystem in use for this scan (``None`` if none/disabled)."""
    if not ctx.options.derivative_fallback:
        return None
    return derivative_fallback_ecosystem(ctx.os)


def os_ecosystems(ctx: ScanContext, ptype: PackageType) -> list[str]:
    """Ecosystems from ``OSInfo.vuln_ecosystems`` whose version ordering fits ``ptype``.

    A derivative-fallback ecosystem is dropped when ``derivative_fallback`` is off.
    """
    out = []
    skip = None if ctx.options.derivative_fallback else derivative_fallback_ecosystem(ctx.os)
    for eco in ctx.os.vuln_ecosystems:
        if eco == skip:
            continue
        etype = ecosystem_package_type(eco)
        if etype == ptype or (etype is None and eco and eco not in LANGUAGE_ECOSYSTEMS.values()):
            out.append(refine_ecosystem(ctx.os, eco))
    return list(dict.fromkeys(out))


def plan_queries(
    ctx: ScanContext, packages: Iterable[Package]
) -> dict[OsvQuery, list[QueryTarget]]:
    """Map every package to its OSV queries (deduplicated across packages)."""
    plan: dict[OsvQuery, list[QueryTarget]] = {}

    def add(q: OsvQuery, t: QueryTarget) -> None:
        if q.name and q.version:
            plan.setdefault(q, []).append(t)

    fallback = fallback_ecosystem(ctx)
    vendors = (ctx.os.id,)
    for pkg in packages:
        if pkg.type in LANGUAGE_ECOSYSTEMS:
            eco = LANGUAGE_ECOSYSTEMS[pkg.type]
            if language_version(pkg) in ("", "(devel)"):
                continue
            add(
                OsvQuery(eco, language_name(pkg), language_version(pkg)),
                QueryTarget(pkg, eco, "package"),
            )
        elif pkg.type in OS_TYPES:
            for req in os_ecosystems(ctx, pkg.type):
                qeco = query_ecosystem(req)
                src = pkg.source_name or pkg.name
                if req == fallback:
                    installed = source_version(pkg)
                    version = strip_derivative_suffix(installed, vendors)
                    derived = installed if version != installed else None
                    target = QueryTarget(pkg, req, "source", derived, fallback=True)
                    add(OsvQuery(qeco, src, version), target)
                    continue
                add(OsvQuery(qeco, src, source_version(pkg)), QueryTarget(pkg, req, "source"))
                if pkg.type == PackageType.RPM and src != pkg.name:
                    add(
                        OsvQuery(qeco, pkg.name, full_version(pkg)), QueryTarget(pkg, req, "binary")
                    )
    return plan


# --------------------------------------------------------------------------- source
class OsvSource(VulnerabilitySource):
    """Matches OS and language packages against OSV.dev."""

    name = "osv"

    def __init__(self, http: HttpClient, *, max_workers: int = 8) -> None:
        self.http = http
        self.max_workers = max(1, max_workers)

    def applicable(self, ctx: ScanContext, packages: list[Package]) -> list[Package]:
        return [
            p
            for p in packages
            if p.type in LANGUAGE_ECOSYSTEMS or (p.type in OS_TYPES and os_ecosystems(ctx, p.type))
        ]

    def match(self, ctx: ScanContext, packages: list[Package]) -> list[Vulnerability]:
        plan = plan_queries(ctx, self.applicable(ctx, packages))
        if not plan:
            return []
        queries = sorted(plan)
        hits, missing = self.query(ctx, queries)
        if missing:
            if self.http.offline:
                ctx.limit(
                    f"offline: no cached vulnerability data for {len(missing)} of {len(queries)}"
                    " OSV package queries; run `startup-sbom db update` or scan online once"
                )
            else:
                ctx.limit(
                    f"osv: {len(missing)} of {len(queries)} package queries failed;"
                    " their vulnerabilities are not assessed"
                )
        wanted: dict[str, str] = {}
        for refs in hits.values():
            for vid, modified in refs:
                wanted[vid] = max(wanted.get(vid, ""), modified)
        records, failed = self.hydrate(wanted)
        if failed:
            ctx.warn(f"osv: could not retrieve {len(failed)} vulnerability records")
            ctx.limit(
                f"osv: {len(failed)} matched vulnerability records could not be retrieved"
                + (" from the offline cache" if self.http.offline else "")
            )
        fragments: list[Fragment] = []
        for q in queries:
            for vid, _ in hits.get(q, []):
                record = records.get(vid)
                if record is None:
                    continue
                for target in plan[q]:
                    fragments.extend(self.fragments(record, q, target))
        ptypes = {p.id: p.type for p in packages}
        return merge_vulnerabilities(fragments, ptypes)

    # -- querying -------------------------------------------------------------
    def query(
        self, ctx: ScanContext, queries: list[OsvQuery]
    ) -> tuple[dict[OsvQuery, list[tuple[str, str]]], list[OsvQuery]]:
        """Resolve queries to ``(id, modified)`` lists; returns ``(hits, unanswered)``."""
        hits: dict[OsvQuery, list[tuple[str, str]]] = {}
        todo: list[OsvQuery] = []
        for q in queries:
            cached = self.http.cache_get_json("osv-query", q.cache_key, QUERY_TTL)
            refs = _refs(cached)
            if refs is None:
                todo.append(q)
            else:
                hits[q] = refs
        if not todo or self.http.offline:
            return hits, todo
        unanswered: list[OsvQuery] = []
        for start in range(0, len(todo), QUERYBATCH_MAX):
            chunk = todo[start : start + QUERYBATCH_MAX]
            try:
                answered = self._querybatch(chunk)
            except NetworkError as exc:
                ctx.warn(f"osv: querybatch failed: {exc}")
                unanswered.extend(todo[start:])
                break
            for q, refs in answered.items():
                hits[q] = refs
                self.http.cache_put_json("osv-query", q.cache_key, [list(r) for r in refs])
        return hits, unanswered

    def _querybatch(self, chunk: list[OsvQuery]) -> dict[OsvQuery, list[tuple[str, str]]]:
        out: dict[OsvQuery, list[tuple[str, str]]] = {q: [] for q in chunk}
        pending: list[tuple[OsvQuery, str | None]] = [(q, None) for q in chunk]
        for _ in range(MAX_PAGES):
            if not pending:
                break
            body = {"queries": [q.payload(tok) for q, tok in pending]}
            resp = self.http.post_json(QUERYBATCH_URL, body)
            try:
                data = resp.json()
            except ValueError as exc:
                raise NetworkError("osv: malformed querybatch response") from exc
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                raise NetworkError("osv: querybatch returned an unexpected number of results")
            nxt: list[tuple[OsvQuery, str | None]] = []
            for (q, _tok), result in zip(pending, results, strict=True):
                if not isinstance(result, dict):
                    continue
                for v in result.get("vulns") or []:
                    if isinstance(v, dict) and isinstance(v.get("id"), str):
                        out[q].append((v["id"], str(v.get("modified", ""))))
                token = result.get("next_page_token")
                if isinstance(token, str) and token:
                    nxt.append((q, token))
            pending = nxt
        else:
            if pending:
                log.warning("osv: pagination limit reached for %d queries", len(pending))
        return {q: sorted(set(refs)) for q, refs in out.items()}

    def hydrate(self, wanted: Mapping[str, str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Fetch full records for ``{id: modified}``; returns ``(records, failed_ids)``."""
        records: dict[str, dict[str, Any]] = {}
        failed: list[str] = []
        if not wanted:
            return records, failed
        if not self.http.offline:
            _ = self.http.client  # create the shared client before worker threads race
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._fetch_record, vid, modified): vid
                for vid, modified in sorted(wanted.items())
            }
            for fut in as_completed(futures):
                vid = futures[fut]
                try:
                    record = fut.result()
                except (NetworkError, ValueError) as exc:
                    log.debug("osv: hydrating %s failed: %s", vid, exc)
                    failed.append(vid)
                    continue
                records[vid] = record
        return records, sorted(failed)

    def _fetch_record(self, vid: str, modified: str) -> dict[str, Any]:
        url = f"{OSV_API}/v1/vulns/{quote(vid, safe=':')}"
        resp = self.http.get(url, ttl=VULN_TTL, cache_key=f"osv-vuln:{vid}@{modified}")
        data = resp.json()
        if not isinstance(data, dict) or data.get("id") != vid:
            raise ValueError(f"unexpected OSV record for {vid}")
        return data

    # -- normalisation --------------------------------------------------------
    def fragments(
        self, record: Mapping[str, Any], q: OsvQuery, target: QueryTarget
    ) -> list[Fragment]:
        """Turn one matched record into per-CVE fragments for ``target.package``."""
        pkg = target.package
        ptype = ecosystem_package_type(target.requested) or pkg.type
        qname = _norm_name(q.ecosystem, q.name)
        entries = [
            e
            for e in record.get("affected") or []
            if isinstance(e, Mapping)
            and isinstance(e.get("package"), Mapping)
            and _norm_name(q.ecosystem, str(e["package"].get("name", ""))) == qname
            and ecosystem_matches(target.requested, str(e["package"].get("ecosystem", "")))
        ]
        confidence = Confidence.HIGH
        note = ""
        if target.requested in STREAM_BASES:
            confidence, note = Confidence.MEDIUM, " (release unknown; all vendor streams)"
        if is_stream_ecosystem(target.requested):
            kept = []
            for entry in entries:
                hit, epoch_ignored = entry_affects(entry, q.version, ptype)
                if hit:
                    kept.append(entry)
                    if epoch_ignored:
                        confidence, note = Confidence.MEDIUM, " (vendor omits epoch)"
            if not kept:
                return []
            entries = kept
        elif not entries:
            confidence, note = Confidence.MEDIUM, " (no affected entry for this ecosystem)"
        if target.fallback:
            # Parent-distribution advisories applied to a derivative: the vendor may
            # ship different builds/patches.  A package carrying the vendor's own
            # revision suffix was modified by it, so its match is weaker still.
            if target.derived_from is not None:
                confidence = Confidence.LOW
                note += f" (derivative fallback; {target.derived_from} compared as {q.version})"
            else:
                confidence = min(confidence, Confidence.MEDIUM, key=_CONF_ORDER.index)
                note += " (derivative fallback)"

        fixed = fixed_versions(entries, q.version, ptype)
        status = VulnStatus.AFFECTED if fixed else distro_status(entries)
        if status is None:
            status = VulnStatus.NO_FIX_AVAILABLE

        rid = str(record["id"])
        cves = record_cves(record)
        ids = cves or [canonical_id(record)]
        weight = 2 if len(ids) == 1 else 1
        aliases = {
            a
            for key in ("aliases", "upstream")
            for a in _str_list(record.get(key))
            if not is_cve(a)
        }
        advisories = {rid} | {r for r in _str_list(record.get("related")) if is_advisory_id(r)}
        reason = f"osv:{target.requested} {target.kind}={q.name} version={q.version}{note}"
        common: dict[str, Any] = {
            "sources": ["osv"],
            "package": pkg.id,
            "package_name": pkg.name,
            "installed_version": pkg.version,
            "fixed_versions": fixed,
            "status": status,
            "summary": osv_summary(record),
            "published": _opt_str(record.get("published")),
            "modified": _opt_str(record.get("modified")),
            "severity": osv_distro_severity(record, entries),
            "cvss": osv_cvss(record, entries),
            "cwes": osv_cwes(record, entries),
            "references": osv_references(record),
            "match_confidence": confidence,
            "match_reason": reason,
        }
        return [
            Fragment(
                Vulnerability(
                    id=vid,
                    aliases=sorted(aliases - {vid}),
                    advisories=sorted(advisories - {vid}),
                    **common,
                ),
                weight,
            )
            for vid in ids
        ]


def _str_list(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _refs(cached: Any) -> list[tuple[str, str]] | None:
    if not isinstance(cached, list):
        return None
    out: list[tuple[str, str]] = []
    for item in cached:
        if not (
            isinstance(item, list) and len(item) == 2 and all(isinstance(x, str) for x in item)
        ):
            return None
        out.append((item[0], item[1]))
    return out
