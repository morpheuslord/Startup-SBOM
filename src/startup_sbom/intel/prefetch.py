"""Intel prefetch orchestration: priorities, budget, concurrency and per-source isolation.

Order of work: select CVEs -> bulk exploit index + EPSS trend batch -> per-CVE
structured sources in a small thread pool -> ranked articles through the
:class:`~startup_sbom.intel.fetcher.SafeFetcher`.  Only structured sources change
``exploitation`` / ``exploit_maturity``; article text only annotates.  Missing data
is recorded in ``IntelBundle.errors`` (and as scan limitations), never as "no exploit".
"""

from __future__ import annotations

import codecs
import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from startup_sbom.context import ScanContext
from startup_sbom.errors import NetworkError
from startup_sbom.intel import sources
from startup_sbom.intel.exploits import MATURITY, ExploitIndex, load_exploit_index
from startup_sbom.intel.extract import MAX_TEXT, analyse, extract_html, extract_text_plain, sanitize
from startup_sbom.intel.fetcher import FetchRefusedError, SafeFetcher
from startup_sbom.intel.search import SearchProvider, search_references
from startup_sbom.intel.select import (
    CVE_RE,
    Candidate,
    Reference,
    Target,
    rank_references,
    select_cves,
)
from startup_sbom.intel.sources import Partial, Signal
from startup_sbom.intel.store import IntelStore, article_id
from startup_sbom.models import IntelBundle, IntelRecord, KEVInfo, OSInfo, Report, Vulnerability
from startup_sbom.net import HttpClient, default_cache_dir
from startup_sbom.textsafe import safe

log = logging.getLogger(__name__)

EXPLOITATION = ("none", "public_poc", "active")
WORKERS = 4
NVD_INTERVAL_KEY = 0.6
NVD_INTERVAL_NOKEY = 6.0
LOOKUP_BUDGET = 120.0
_last_root: Path | None = None
_root_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _remember_root(root: Path) -> None:
    global _last_root  # noqa: PLW0603 - process-wide hint for article_text()
    with _root_lock:
        _last_root = root


class _Pacer:
    """Serialises calls to a rate-limited API with a minimum interval."""

    def __init__(self, interval: float, sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval = interval
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last: float | None = None

    def run(self, fn: Callable[[], Partial]) -> Partial:
        with self._lock:
            if self._last is not None:
                gap = self.interval - (time.monotonic() - self._last)
                if gap > 0:
                    self._sleep(gap)
            try:
                return fn()
            finally:
                self._last = time.monotonic()


@dataclass(slots=True)
class _Config:
    http: HttpClient
    store: IntelStore
    index: ExploitIndex
    deadline: float
    budget: float
    ttl: float
    os_info: OSInfo | None
    trends: dict[str, list[tuple[str, float]]] = field(default_factory=dict)
    trend_error: str | None = None
    fetcher: SafeFetcher | None = None
    articles: bool = True
    max_articles: int = 4
    nvd_key: str | None = None
    nvd_unkeyed: bool = False
    github: bool = False
    search: SearchProvider | None = None
    kev: dict[str, KEVInfo] = field(default_factory=dict)
    pacer: _Pacer = field(default_factory=lambda: _Pacer(NVD_INTERVAL_KEY))

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def remaining(self) -> float:
        return self.deadline - time.monotonic()


# --------------------------------------------------------------------------- articles
def _decode(body: bytes, charset: str | None) -> str:
    try:
        codec = codecs.lookup(charset or "utf-8").name
    except LookupError:
        codec = "utf-8"
    return body.decode(codec, "replace")


def fetch_article(cfg: _Config, cand: Candidate, cve: str) -> IntelRecord:
    """One article through the SafeFetcher (cached 7 days); text goes to the cache only."""
    cached = cfg.store.load_article(cand.url)
    if cached is not None:
        return cached
    if cfg.fetcher is None:
        raise FetchRefusedError("article fetching disabled")
    result = cfg.fetcher.fetch(cand.url)
    aid = article_id(cand.url)
    host = urlsplit(result.url).hostname or ""
    final = result.url if result.url != cand.url else None
    if result.status != 200 or result.body is None:
        record = IntelRecord(
            id=aid,
            source="article",
            url=cand.url,
            final_url=final,
            kind=cand.kind,
            site=host,
            cves=[cve],
            fetched_at=result.fetched_at.replace(microsecond=0),
            trust="unstructured",
            http_status=result.status,
            content_type=result.content_type or None,
        )
        cfg.store.save_article(cand.url, record, None)
        return record
    raw = _decode(result.body, result.charset)
    plain = result.content_type in ("text/plain", "application/json")
    extracted = extract_text_plain(raw) if plain else extract_html(raw)
    info = analyse(extracted.text, cve, plain=plain)
    maturity = "poc" if cand.kind == "exploit" or len(info.exploit_indicators) >= 3 else None
    record = IntelRecord(
        id=aid,
        source="article",
        url=cand.url,
        final_url=final,
        kind=cand.kind,
        title=extracted.title,
        site=extracted.site_name or host,
        published=extracted.published,
        snippet=info.snippet or (sanitize(extracted.description or "", 600) or None),
        cves=info.cves or [cve],
        fetched_at=result.fetched_at.replace(microsecond=0),
        trust="unstructured",
        exploit_maturity=maturity,
        http_status=result.status,
        content_type=result.content_type,
        sha256=hashlib.sha256(result.body).hexdigest(),
        truncated=result.truncated or len(extracted.text) >= MAX_TEXT,
        text_ref=aid if extracted.text else None,
    )
    cfg.store.save_article(cand.url, record, extracted.text)
    return record


# --------------------------------------------------------------------------- one CVE
def _merge(
    bundle: IntelBundle, part: Partial, refs: list[Reference], signals: list[Signal]
) -> None:
    refs.extend(part.refs)
    signals.extend(part.signals)
    bundle.advisories.extend(part.advisories)
    bundle.vendor_status.extend(part.vendor)
    if part.cisa_ssvc:
        bundle.cisa_ssvc = part.cisa_ssvc
    if part.kev is not None and bundle.kev is None:
        bundle.kev = part.kev
    if part.poc_count is not None:
        bundle.poc_repos_count = part.poc_count
        bundle.poc_repos_top = part.poc_top


def _finalise(bundle: IntelBundle, signals: list[Signal]) -> IntelBundle:
    exploitation = max((s.exploitation for s in signals), key=EXPLOITATION.index, default="none")
    maturity = max((s.maturity for s in signals), key=MATURITY.index, default="none")
    bundle.exploitation = exploitation
    bundle.exploit_maturity = maturity
    bundle.exploit_available = exploitation != "none" or maturity != "none"
    bundle.exploit_sources = sorted({s.source for s in signals})
    bundle.vendor_status.sort(key=lambda v: v.vendor)
    bundle.advisories.sort(key=lambda r: (r.source, r.url))
    bundle.errors = sorted(dict.fromkeys(bundle.errors))
    return bundle


def _steps(cfg: _Config, cve: str, now: datetime) -> list[tuple[str, Callable[[], Partial]]]:
    http, ttl = cfg.http, cfg.ttl
    steps: list[tuple[str, Callable[[], Partial]]] = [
        ("cve.org", lambda: sources.cve_services(http, cve, ttl=ttl, now=now)),
    ]
    if sources.ubuntu_relevant(cfg.os_info):
        steps.append(("ubuntu", lambda: sources.ubuntu(http, cve, ttl=ttl, os_info=cfg.os_info)))
    if sources.redhat_relevant(cfg.os_info):
        steps.append(("redhat", lambda: sources.redhat(http, cve, ttl=ttl, os_info=cfg.os_info)))
    steps.append(("poc-in-github", lambda: sources.poc_in_github(http, cve, ttl=ttl)))
    if cfg.github:
        steps.append(("ghsa", lambda: sources.ghsa(http, cve, ttl=ttl, now=now)))
    if cfg.nvd_key or cfg.nvd_unkeyed:
        steps.append(("nvd", lambda: _nvd(cfg, cve)))
    return steps


def _nvd(cfg: _Config, cve: str) -> Partial:
    """NVD reference tags: paced; without a key only while half the budget is left."""
    if cfg.http.offline:
        return sources.nvd(cfg.http, cve, ttl=cfg.ttl, api_key=cfg.nvd_key)
    if not cfg.nvd_key and cfg.remaining() < cfg.budget / 2 + cfg.pacer.interval:
        return Partial()
    return cfg.pacer.run(lambda: sources.nvd(cfg.http, cve, ttl=cfg.ttl, api_key=cfg.nvd_key))


def build_bundle(cfg: _Config, cve: str, vulns: tuple[Vulnerability, ...] = ()) -> IntelBundle:
    """Gather everything for ``cve``; every source failure lands in ``errors``."""
    now = _now()
    bundle = IntelBundle(cve=cve, fetched_at=now)
    refs: list[Reference] = []
    signals: list[Signal] = []
    for vuln in vulns:
        if vuln.kev is not None:
            bundle.kev = bundle.kev or vuln.kev
            signals.append(Signal("active", "functional", "cisa-kev"))
        refs.extend(Reference(u, "osv") for u in vuln.references)
    if bundle.kev is None and cve in cfg.kev:
        bundle.kev = cfg.kev[cve]
        signals.append(Signal("active", "functional", "cisa-kev"))
    if cfg.index.available:
        bundle.exploitdb, bundle.metasploit, bundle.nuclei = cfg.index.refs(cve)
        signals.extend(Signal("public_poc", m, s) for m, s in cfg.index.maturity(cve))
        bundle.errors.extend(e for e in cfg.index.errors if "stale" in e)
    else:
        bundle.errors.append(
            "exploit index unavailable: Exploit-DB, Metasploit and nuclei not consulted"
        )
    bundle.epss_trend = list(cfg.trends.get(cve, []))
    if cfg.trend_error:
        bundle.errors.append(f"epss trend: {cfg.trend_error}")

    for name, step in _steps(cfg, cve, now):
        if cfg.expired():
            bundle.errors.append(f"{name}: skipped (intel time budget exhausted)")
            continue
        try:
            part = step()
        except Exception as exc:  # noqa: BLE001 - per-source isolation, recorded below
            bundle.errors.append(f"{name}: {safe(exc, 200)}")
            continue
        _merge(bundle, part, refs, signals)

    if cfg.search is not None and not cfg.expired():
        try:
            refs.extend(search_references(cfg.search, cve))
        except Exception as exc:  # noqa: BLE001 - optional plug-in
            bundle.errors.append(f"search:{cfg.search.name}: {safe(exc, 200)}")
    if cfg.articles and cfg.max_articles > 0:
        _articles(cfg, bundle, refs)
    return _finalise(bundle, signals)


def _articles(cfg: _Config, bundle: IntelBundle, refs: list[Reference]) -> None:
    for cand in rank_references(refs, cfg.max_articles):
        host = urlsplit(cand.url).hostname or "?"
        if cfg.fetcher is None:  # offline: cached copies only (any age)
            cached = cfg.store.load_article_any_age(cand.url)
            if cached is not None:
                bundle.articles.append(cached)
            else:
                bundle.errors.append(f"article {host}: not cached (offline)")
            continue
        if cfg.expired():
            bundle.errors.append("articles: skipped (intel time budget exhausted)")
            break
        try:
            bundle.articles.append(fetch_article(cfg, cand, bundle.cve))
        except (FetchRefusedError, httpx.HTTPError, NetworkError, OSError) as exc:
            bundle.errors.append(f"article {host}: {type(exc).__name__}: {safe(exc, 160)}")


# --------------------------------------------------------------------------- setup
def _nvd_key(ctx: ScanContext | None) -> str | None:
    key = (ctx.options.nvd_api_key if ctx else None) or os.environ.get("NVD_API_KEY", "")
    return key.strip() or None


def _make_fetcher(http: HttpClient, store: IntelStore) -> SafeFetcher | None:
    if http.offline:
        return None
    return SafeFetcher(store=store)


def _config(
    http: HttpClient,
    *,
    budget: float,
    ttl: float,
    os_info: OSInfo | None,
    articles: bool,
    max_articles: int,
    nvd_key: str | None,
    nvd_unkeyed: bool,
    cves: list[str],
    refresh_index: bool = False,
    search: SearchProvider | None = None,
    fetcher: SafeFetcher | None = None,
) -> _Config:
    store = IntelStore(http.cache_dir / "intel")
    _remember_root(store.root)
    deadline = time.monotonic() + max(0.0, budget)
    try:
        index = load_exploit_index(http, store, refresh=refresh_index)
    except Exception as exc:  # noqa: BLE001 - index failure must not stop prefetch
        index = ExploitIndex(errors=[f"exploit index: {safe(exc, 200)}"])
    cfg = _Config(
        http=http,
        store=store,
        index=index,
        deadline=deadline,
        budget=max(0.0, budget),
        ttl=ttl,
        os_info=os_info,
        articles=articles,
        max_articles=max_articles,
        nvd_key=nvd_key,
        nvd_unkeyed=nvd_unkeyed,
        github=bool(os.environ.get("GITHUB_TOKEN", "").strip()),
        search=search,
        pacer=_Pacer(NVD_INTERVAL_KEY if nvd_key else NVD_INTERVAL_NOKEY),
    )
    if cves and not cfg.expired():
        try:
            cfg.trends = sources.epss_trends(http, cves, ttl=ttl)
        except Exception as exc:  # noqa: BLE001 - isolated per source
            cfg.trend_error = safe(exc, 200)
    if articles and max_articles > 0:
        cfg.fetcher = fetcher if fetcher is not None else _make_fetcher(http, store)
    return cfg


def _cached(cfg: _Config, cve: str, refresh: bool) -> IntelBundle | None:
    if refresh:
        return None
    hit = cfg.store.load_bundle(cve)
    if hit is None:
        return None
    bundle, stale = hit
    if cfg.http.offline:
        if stale:
            bundle.errors = sorted(
                {
                    *bundle.errors,
                    f"served from stale intel cache (fetched {bundle.fetched_at:%Y-%m-%d})",
                }
            )
        return bundle
    return bundle if not stale and not bundle.errors else None


# --------------------------------------------------------------------------- public
def prefetch(
    report: Report,
    ctx: ScanContext,
    http: HttpClient,
    *,
    search: SearchProvider | None = None,
    fetcher: SafeFetcher | None = None,
) -> list[IntelBundle]:
    """Prefetch intel for the report's top CVEs (opt-in; caller checks ``prefetch_intel``)."""
    opts = ctx.options
    targets, leftover = select_cves(report, opts.intel_max_cves)
    if leftover:
        ctx.limit(
            f"intel prefetch: {len(leftover)} lower-priority CVE(s) not prefetched "
            f"(intel_max_cves={opts.intel_max_cves})"
        )
    if not targets:
        return []
    nvd_key = _nvd_key(ctx)
    cfg = _config(
        http,
        budget=opts.intel_budget,
        ttl=sources.TTL,
        os_info=report.os,
        articles=opts.intel_articles,
        max_articles=opts.intel_max_articles,
        nvd_key=nvd_key,
        nvd_unkeyed=True,
        cves=[t.cve for t in targets],
        search=search,
        fetcher=fetcher,
    )
    if not nvd_key:
        ctx.limit("intel: NVD reference tags consulted only within the time budget (no API key)")
    if not cfg.github:
        ctx.limit("intel: GitHub advisories skipped (no GITHUB_TOKEN)")
    if not cfg.index.available:
        ctx.limit("intel: exploit index unavailable; public exploit availability not assessed")
    if http.offline:
        ctx.limit("intel: offline, cached intel only (articles not fetched)")
    owned = fetcher is None and cfg.fetcher is not None
    try:
        results = _run(cfg, targets, ctx)
    finally:
        if owned and cfg.fetcher is not None:
            cfg.fetcher.close()
    incomplete = sum(1 for b in results if b.errors)
    if incomplete:
        ctx.limit(f"intel: {incomplete} of {len(targets)} CVE(s) have incomplete intel")
    return results


def _run(cfg: _Config, targets: list[Target], ctx: ScanContext) -> list[IntelBundle]:
    done: dict[str, IntelBundle] = {}
    todo = []
    for target in targets:
        cached = _cached(cfg, target.cve, refresh=False)
        if cached is not None:
            done[target.cve] = cached
        else:
            todo.append(target)
    pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="intel")
    futures: dict[Future[IntelBundle], str] = {}
    try:
        for target in todo:
            fut = pool.submit(build_bundle, cfg, target.cve, target.vulnerabilities)
            futures[fut] = target.cve
        pending = set(futures)
        while pending:
            timeout = max(0.0, cfg.remaining()) + 2.0  # grace for in-flight requests
            finished, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
            if not finished:
                break
            for fut in finished:
                cve = futures[fut]
                try:
                    bundle = fut.result()
                except Exception as exc:
                    log.debug("intel bundle for %s failed", cve, exc_info=True)
                    ctx.warn(f"intel prefetch for {cve} failed: {safe(exc, 200)}")
                    continue
                done[cve] = bundle
                if not cfg.http.offline:
                    cfg.store.save_bundle(bundle)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    missing = [t.cve for t in targets if t.cve not in done]
    if missing:
        shown = ", ".join(missing[:10]) + (
            f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""
        )
        ctx.limit(
            f"intel prefetch budget ({cfg.budget:g}s) exhausted: "
            f"{len(missing)} CVE(s) not prefetched: {shown}"
        )
    return [done[t.cve] for t in targets if t.cve in done]


def lookup(
    cve: str, http: HttpClient, *, articles: bool = True, refresh: bool = False
) -> IntelBundle:
    """Standalone single-CVE lookup (all structured sources; articles optional)."""
    cve = cve.strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"not a CVE id: {cve!r}")
    nvd_key = _nvd_key(None)
    cfg = _config(
        http,
        budget=LOOKUP_BUDGET,
        ttl=0.0 if refresh else sources.TTL,
        os_info=None,
        articles=articles,
        max_articles=4,
        nvd_key=nvd_key,
        nvd_unkeyed=True,
        cves=[cve],
    )
    try:
        cached = _cached(cfg, cve, refresh)
        if cached is not None and (cached.articles or not articles or http.offline):
            return cached
        try:
            from startup_sbom.vulns.kev import load_kev

            entry = load_kev(http).entries.get(cve)
            if entry is not None:
                cfg.kev[cve] = entry
        except Exception as exc:  # noqa: BLE001 - KEV is one source among many
            log.debug("kev lookup failed: %s", safe(exc))
        bundle = build_bundle(cfg, cve)
        if not http.offline:
            cfg.store.save_bundle(bundle)
        return bundle
    finally:
        if cfg.fetcher is not None:
            cfg.fetcher.close()


def article_text(record: IntelRecord, *, cache_dir: Path | None = None) -> str | None:
    """Cached cleaned full text of an article (untrusted: wrap with untrusted_block)."""
    if not record.text_ref:
        return None
    if cache_dir is not None:
        root = cache_dir / "intel"
    else:
        with _root_lock:
            root = _last_root or default_cache_dir() / "intel"
    return IntelStore(root).article_text(record.text_ref)
