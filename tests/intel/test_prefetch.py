"""Prefetch orchestration: budgets, offline, isolation, determinism, lookup, articles."""

from __future__ import annotations

import importlib
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intel.helpers import (
    FakeFeeds,
    FakeWeb,
    load,
    make_fetcher,
    make_report,
    make_threat,
    make_vuln,
)
from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.intel import article_text, lookup, prefetch
from startup_sbom.models import KEVInfo, OSInfo, Report
from startup_sbom.net import HttpClient
from startup_sbom.rootfs import DirectoryRootFS

# the package re-exports the function under the submodule's name, so go via importlib
prefetch_mod = importlib.import_module("startup_sbom.intel.prefetch")

ARTICLE_DNS = {
    "santandersecurityresearch.github.io": ["185.199.108.153"],
    "www.openwall.com": ["193.110.157.242"],
}
OPENWALL_TEXT = (
    "oss-security - regreSSHion advisory\n"
    "\n"
    "The signal handler race condition in sshd (CVE-2024-6387) was confirmed to be\n"
    "exploitable on 32-bit systems; a proof-of-concept exploit needs about 10k tries.\n"
)


@pytest.fixture(autouse=True)
def _no_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(prefetch_mod, "NVD_INTERVAL_NOKEY", 0.0)


@pytest.fixture
def make_ctx(tmp_path: Path) -> Callable[..., ScanContext]:
    root = tmp_path / "rootfs"
    root.mkdir(exist_ok=True)

    def _make(**options: Any) -> ScanContext:
        return ScanContext(fs=DirectoryRootFS(root), options=ScanOptions(**options))

    return _make


def _report() -> Report:
    vulns = [
        make_vuln("CVE-2024-6387", package="pkg:deb/openssh"),
        make_vuln("CVE-2021-3156", package="pkg:deb/sudo", kev=KEVInfo(date_added="2022-04-06")),
    ]
    threats = [
        make_threat("CVE-2024-6387", risk_score=80.0),
        make_threat("CVE-2021-3156", risk_score=70.0),
    ]
    report = make_report(vulns, threats)
    report.os = OSInfo(id="ubuntu", id_like=["debian"], version_codename="noble")
    return report


def _web_with_articles() -> FakeWeb:
    web = FakeWeb()
    web.add_page(
        "https://santandersecurityresearch.github.io/blog/sshing_the_masses.html",
        load("article.html"),
    )
    web.add_page(
        "https://www.openwall.com/lists/oss-security/2024/07/03/11",
        OPENWALL_TEXT,
        content_type="text/plain",
    )
    return web


def _strip_volatile(dump: Any) -> Any:
    if isinstance(dump, dict):
        return {k: _strip_volatile(v) for k, v in dump.items() if k != "fetched_at"}
    if isinstance(dump, list):
        return [_strip_volatile(v) for v in dump]
    return dump


# --------------------------------------------------------------------------- end to end
def test_prefetch_end_to_end(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(prefetch_intel=True, intel_max_articles=2)
    web = _web_with_articles()
    with make_fetcher(web, dns=ARTICLE_DNS) as fetcher:
        bundles = prefetch(_report(), ctx, make_http(), fetcher=fetcher)
    # the KEV-listed CVE ranks first
    assert [b.cve for b in bundles] == ["CVE-2021-3156", "CVE-2024-6387"]

    samedit, regresshion = bundles
    assert regresshion.exploitation == "public_poc"  # ADP "poc" normalised; never "active"
    assert regresshion.exploit_maturity == "functional"  # nuclei template beats unverified EDB
    assert regresshion.exploit_available
    assert regresshion.exploit_sources == [
        "cisa-ssvc",
        "exploitdb",
        "nuclei",
        "nvd-exploit-tag",
        "poc-in-github",
    ]
    assert [e.id for e in regresshion.exploitdb] == ["52269"]
    assert regresshion.poc_repos_count == 2
    assert regresshion.poc_repos_top[0].full_name == "xaitax/CVE-2024-6387_Check"
    # the target is Ubuntu, so Red Hat per-CVE JSON is not consulted
    assert [v.vendor for v in regresshion.vendor_status] == ["ubuntu"]
    assert regresshion.vendor_status[0].advisories == ["USN-6859-1"]
    assert regresshion.epss_trend[-1] == ("2026-10-09", 0.99506)
    assert regresshion.cisa_ssvc["Exploitation"] == "public_poc"

    assert samedit.exploitation == "active"  # KEV + ADP active
    assert samedit.exploit_maturity == "weaponized"  # MSF exploit module, rank 600
    assert "cisa-kev" in samedit.exploit_sources
    assert "metasploit" in samedit.exploit_sources

    # articles came through the SafeFetcher only, with sanitised snippets
    urls = {a.url for a in regresshion.articles}
    assert urls == {
        "https://santandersecurityresearch.github.io/blog/sshing_the_masses.html",
        "https://www.openwall.com/lists/oss-security/2024/07/03/11",
    }
    for article in regresshion.articles:
        assert article.trust == "unstructured"
        assert "IGNORE" not in (article.snippet or "")
    html_article = next(a for a in regresshion.articles if a.url.endswith(".html"))
    assert html_article.title is not None
    assert html_article.text_ref is not None
    text = article_text(html_article)
    assert text is not None
    assert "race in sshd's SIGALRM handler" in text
    assert "IGNORE PREVIOUS" not in text


def test_prefetch_bundles_are_deterministic(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext], tmp_path: Path
) -> None:
    web = _web_with_articles()
    dumps = []
    for run in ("one", "two"):
        ctx = make_ctx(prefetch_intel=True, intel_max_articles=2)
        with make_fetcher(web, dns=ARTICLE_DNS) as fetcher:
            bundles = prefetch(_report(), ctx, make_http(cache=tmp_path / run), fetcher=fetcher)
        dumps.append([_strip_volatile(b.model_dump(mode="json")) for b in bundles])
    assert dumps[0] == dumps[1]


def test_prefetch_respects_max_cves_and_records_leftovers(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(prefetch_intel=True, intel_max_cves=1, intel_articles=False)
    bundles = prefetch(_report(), ctx, make_http())
    assert [b.cve for b in bundles] == ["CVE-2021-3156"]  # KEV outranks risk score
    assert any("1 lower-priority CVE(s) not prefetched" in li for li in ctx.limitations)


def test_prefetch_nothing_selected(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(prefetch_intel=True)
    assert prefetch(make_report(), ctx, make_http()) == []


# --------------------------------------------------------------------------- isolation
def test_per_source_failure_is_isolated(
    make_http: Callable[..., HttpClient],
    make_ctx: Callable[..., ScanContext],
    feeds: FakeFeeds,
) -> None:
    feeds.fail["ubuntu.com"] = 500
    ctx = make_ctx(prefetch_intel=True, intel_articles=False)
    bundles = prefetch(_report(), ctx, make_http())
    assert len(bundles) == 2
    bundle = next(b for b in bundles if b.cve == "CVE-2024-6387")
    assert any(e.startswith("ubuntu:") for e in bundle.errors)  # failure recorded
    # every other source still contributed
    assert bundle.poc_repos_count == 2
    assert bundle.cisa_ssvc["Exploitation"] == "public_poc"
    assert bundle.epss_trend
    assert bundle.exploitation == "public_poc"
    assert any("incomplete intel" in li for li in ctx.limitations)


def test_trend_failure_is_isolated(
    make_http: Callable[..., HttpClient],
    make_ctx: Callable[..., ScanContext],
    feeds: FakeFeeds,
) -> None:
    feeds.fail["api.first.org"] = 503
    ctx = make_ctx(prefetch_intel=True, intel_articles=False)
    bundles = prefetch(_report(), ctx, make_http())
    assert all(b.epss_trend == [] for b in bundles)
    assert all(any(e.startswith("epss trend:") for e in b.errors) for b in bundles)
    assert all(b.exploitation != "none" for b in bundles)  # the rest still ran


def test_article_failures_do_not_poison_the_bundle(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    web = FakeWeb()  # no pages, and only santander resolves
    dns = {"santandersecurityresearch.github.io": ["185.199.108.153"]}
    ctx = make_ctx(prefetch_intel=True, intel_max_articles=2)
    with make_fetcher(web, dns=dns) as fetcher:
        bundles = prefetch(_report(), ctx, make_http(), fetcher=fetcher)
    bundle = next(b for b in bundles if b.cve == "CVE-2024-6387")
    assert bundle.exploitation == "public_poc"  # structured intel is intact
    assert any(e.startswith("article www.openwall.com: FetchRefusedError") for e in bundle.errors)
    assert all(a.http_status == 404 for a in bundle.articles)


# --------------------------------------------------------------------------- budget
def test_budget_expiry_becomes_limitation_never_no_exploit(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(prefetch_intel=True, intel_budget=0.0, intel_articles=False)
    bundles = prefetch(_report(), ctx, make_http())
    for bundle in bundles:
        skipped = [e for e in bundle.errors if "intel time budget exhausted" in e]
        assert skipped  # every structured step was skipped and recorded
        assert not bundle.advisories
        assert not bundle.vendor_status
    assert any("incomplete intel" in li for li in ctx.limitations)
    # the bulk exploit index was already fetched, so its facts may still be present;
    # what must never happen is an invented "none" from a skipped source
    assert all("no exploit" not in e.lower() for b in bundles for e in b.errors)


def test_deadline_skips_leftover_cves(
    make_http: Callable[..., HttpClient],
    make_ctx: Callable[..., ScanContext],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When workers outlive the budget, unfinished CVEs land in a limitation."""
    ctx = make_ctx(prefetch_intel=True, intel_budget=0.05, intel_articles=False)

    slow = prefetch_mod.build_bundle

    def stall(cfg: Any, cve: str, vulns: Any = ()) -> Any:
        time.sleep(0.2 if cve == "CVE-2021-3156" else 0.0)
        return slow(cfg, cve, vulns)

    monkeypatch.setattr(prefetch_mod, "build_bundle", stall)
    bundles = prefetch_mod.prefetch(_report(), ctx, make_http())
    done = {b.cve for b in bundles}
    if "CVE-2021-3156" not in done:
        assert any("not prefetched: CVE-2021-3156" in li for li in ctx.limitations)


# --------------------------------------------------------------------------- offline
def test_offline_cold_cache_everything_is_a_gap(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(offline=True, prefetch_intel=True)
    bundles = prefetch(_report(), ctx, make_http(offline=True))
    assert len(bundles) == 2
    for bundle in bundles:
        assert bundle.exploitation in ("none", "active")  # KEV from the report may remain
        assert any("offline" in e for e in bundle.errors)
    assert any("exploit index unavailable" in li for li in ctx.limitations)
    assert any("offline, cached intel only" in li for li in ctx.limitations)
    # the KEV info carried by the report itself is still used
    samedit = next(b for b in bundles if b.cve == "CVE-2021-3156")
    assert samedit.exploitation == "active"
    assert samedit.kev is not None


def test_offline_serves_cached_bundles_and_flags_stale(
    make_http: Callable[..., HttpClient],
    make_ctx: Callable[..., ScanContext],
    tmp_path: Path,
) -> None:
    cache = tmp_path / "warm"
    ctx = make_ctx(prefetch_intel=True, intel_articles=False)
    online = prefetch(_report(), ctx, make_http(cache=cache))
    assert all(not b.errors for b in online)

    # age the cached bundles beyond the 24 h TTL
    old = time.time() - 3 * 86400
    for path in (cache / "intel" / "cve").glob("*.json"):
        os.utime(path, (old, old))

    ctx2 = make_ctx(offline=True, prefetch_intel=True, intel_articles=False)
    offline = prefetch(_report(), ctx2, make_http(offline=True, cache=cache))
    assert [b.cve for b in offline] == [b.cve for b in online]
    for bundle in offline:
        assert any(e.startswith("served from stale intel cache") for e in bundle.errors)
    regresshion = next(b for b in offline if b.cve == "CVE-2024-6387")
    assert regresshion.exploitation == "public_poc"  # the cached facts survive


def test_offline_articles_not_cached_is_an_error_not_a_fetch(
    make_http: Callable[..., HttpClient], make_ctx: Callable[..., ScanContext]
) -> None:
    ctx = make_ctx(offline=True, prefetch_intel=True, intel_max_articles=2)
    bundles = prefetch(_report(), ctx, make_http(offline=True))
    bundle = next(b for b in bundles if b.cve == "CVE-2024-6387")
    assert bundle.articles == []
    # candidate articles exist only if refs were cached; offline cold cache has none,
    # and no SafeFetcher was ever constructed
    assert all("article" not in e or "not cached (offline)" in e for e in bundle.errors)


# --------------------------------------------------------------------------- lookup
def test_lookup_single_cve(make_http: Callable[..., HttpClient], feeds: FakeFeeds) -> None:
    bundle = lookup("cve-2024-6387", make_http(), articles=False)
    assert bundle.cve == "CVE-2024-6387"
    assert bundle.exploitation == "public_poc"
    assert {v.vendor for v in bundle.vendor_status} == {"ubuntu", "redhat"}

    calls_after_first = len(feeds.calls)
    again = lookup("CVE-2024-6387", make_http(), articles=False)
    assert len(feeds.calls) == calls_after_first  # served from the bundle cache
    assert _strip_volatile(again.model_dump(mode="json")) == _strip_volatile(
        bundle.model_dump(mode="json")
    )

    lookup("CVE-2024-6387", make_http(), articles=False, refresh=True)
    assert len(feeds.calls) > calls_after_first  # refresh revalidates


def test_lookup_rejects_non_cve(make_http: Callable[..., HttpClient]) -> None:
    with pytest.raises(ValueError, match="not a CVE id"):
        lookup("GHSA-xxxx-yyyy-zzzz", make_http())
    with pytest.raises(ValueError, match="not a CVE id"):
        lookup("CVE-2024-6387; rm -rf /", make_http())


def test_article_text_requires_valid_ref(tmp_path: Path) -> None:
    from startup_sbom.models import IntelRecord

    record = IntelRecord(
        id="a" * 32,
        source="article",
        url="https://example.org/x",
        kind="writeup",
        fetched_at=prefetch_mod._now(),
        text_ref="../../etc/passwd",
    )
    assert article_text(record, cache_dir=tmp_path) is None  # ids only, no paths
