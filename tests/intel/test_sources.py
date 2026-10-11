"""Structured per-CVE source parsers (CVE Services / NVD / vendors / PoC / EPSS)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from intel.helpers import FakeFeeds, load_json
from startup_sbom.intel.sources import (
    epss_trends,
    ghsa,
    normalise_ssvc,
    parse_cve_record,
    parse_epss_trends,
    parse_nvd,
    parse_poc_repos,
    parse_redhat,
    parse_ubuntu,
    poc_in_github,
    redhat_relevant,
    ubuntu,
    ubuntu_relevant,
)
from startup_sbom.models import OSInfo
from startup_sbom.net import HttpClient

NOW = datetime(2026, 10, 10, tzinfo=UTC)


# --------------------------------------------------------------------------- CVE Services
def test_adp_poc_normalised_to_public_poc() -> None:
    part = parse_cve_record(load_json("cve_CVE-2024-6387.json"), "CVE-2024-6387", NOW)
    assert part.cisa_ssvc["Exploitation"] == "public_poc"  # ADP says "poc" (SSVC 2.0.3)
    assert part.kev is None
    (signal,) = part.signals
    assert (signal.exploitation, signal.source) == ("public_poc", "cisa-ssvc")


def test_adp_active_and_kev_metric() -> None:
    part = parse_cve_record(load_json("cve_CVE-2021-3156.json"), "CVE-2021-3156", NOW)
    assert part.cisa_ssvc["Exploitation"] == "active"
    assert part.kev is not None
    assert part.kev.date_added == "2022-04-06"
    assert {(s.exploitation, s.source) for s in part.signals} == {
        ("active", "cisa-ssvc"),
        ("active", "cisa-kev"),
    }


def test_cve_record_refs_and_advisory() -> None:
    part = parse_cve_record(load_json("cve_CVE-2024-6387.json"), "CVE-2024-6387", NOW)
    by_origin = {r.origin for r in part.refs}
    assert by_origin == {"cna", "cve-adp"}
    assert any("qualys.com" in r.url for r in part.refs)
    (advisory,) = part.advisories
    assert advisory.source == "cve.org"
    assert advisory.trust == "structured"
    assert advisory.title is not None
    assert "race condition" in (advisory.snippet or "")


def test_normalise_ssvc_handles_garbage() -> None:
    assert normalise_ssvc(None) == {}
    assert normalise_ssvc([{"Exploitation": "poc"}, "junk", {"X": 1}]) == {
        "Exploitation": "public_poc"
    }


# --------------------------------------------------------------------------- NVD
def test_nvd_exploit_tag_signal() -> None:
    part = parse_nvd(load_json("nvd_CVE-2024-6387.json"), "CVE-2024-6387")
    (signal,) = part.signals
    assert (signal.exploitation, signal.maturity, signal.source) == (
        "public_poc",
        "poc",
        "nvd-exploit-tag",
    )
    exploit_refs = [r for r in part.refs if "Exploit" in r.tags]
    assert len(exploit_refs) == 2
    assert part.kev is None


def test_nvd_empty_response() -> None:
    part = parse_nvd({"vulnerabilities": []}, "CVE-2020-0001")
    assert part.signals == []
    assert part.refs == []


# --------------------------------------------------------------------------- vendors
def test_ubuntu_vendor_status() -> None:
    os_info = OSInfo(id="ubuntu", version_codename="noble")
    part = parse_ubuntu(load_json("ubuntu_CVE-2024-6387.json"), "CVE-2024-6387", os_info)
    (vendor,) = part.vendor
    assert vendor.vendor == "ubuntu"
    assert vendor.severity == "high"
    assert vendor.advisories == ["USN-6859-1"]
    assert vendor.status == "openssh: released (1:9.6p1-3ubuntu13.3)"
    assert "LoginGraceTime" in (vendor.mitigation or "")
    assert part.signals == []  # vendor data never changes exploitation
    assert any("qualys.com" in r.url for r in part.refs)


def test_redhat_vendor_status_and_newline_joined_refs() -> None:
    os_info = OSInfo(id="rhel", version_id="9.4", family="rhel")
    part = parse_redhat(load_json("redhat_CVE-2024-6387.json"), "CVE-2024-6387", os_info)
    (vendor,) = part.vendor
    assert vendor.severity == "Important"
    assert vendor.status == "fixed in RHSA-2024:4312"
    assert vendor.advisories == ["RHSA-2024:4312", "RHSA-2024:4457"]
    assert "ExecShield" in (vendor.statement or "")
    assert "LoginGraceTime" in (vendor.mitigation or "")
    # the single "references" string is newline-joined and must be split
    assert sorted(r.url for r in part.refs) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "https://santandersecurityresearch.github.io/blog/sshing_the_masses.html",
        "https://www.cve.org/CVERecord?id=CVE-2024-6387",
    ]


def test_vendor_relevance() -> None:
    assert ubuntu_relevant(OSInfo(id="ubuntu"))
    assert ubuntu_relevant(OSInfo(id="debian"))
    assert ubuntu_relevant(OSInfo())  # unknown target: upstream context is still useful
    assert not ubuntu_relevant(OSInfo(id="alpine"))
    assert redhat_relevant(OSInfo(id="rocky", id_like=["rhel"]))
    assert redhat_relevant(OSInfo(id="fedora"))
    assert not redhat_relevant(OSInfo(id="alpine"))


def test_vendor_404_is_empty_not_error(make_http: Callable[..., HttpClient]) -> None:
    http = make_http()
    part = ubuntu(http, "CVE-1999-0001", ttl=0.0)
    assert part.vendor == []
    assert part.refs == []


# --------------------------------------------------------------------------- PoC-in-GitHub
def test_poc_repos_metadata_only() -> None:
    part = parse_poc_repos(load_json("poc_CVE-2024-6387.json"))
    assert part.poc_count == 2  # the fork is excluded
    assert [r.full_name for r in part.poc_top] == [
        "xaitax/CVE-2024-6387_Check",
        "zgzhang/cve-2024-6387-poc",
    ]
    assert part.poc_top[0].stars == 526
    assert part.poc_top[0].untrusted is True
    assert "\x1b" not in (part.poc_top[1].description or "")  # ANSI stripped
    (signal,) = part.signals
    assert (signal.exploitation, signal.maturity) == ("public_poc", "poc")


def test_poc_repos_404_means_zero_but_no_signal(make_http: Callable[..., HttpClient]) -> None:
    part = poc_in_github(make_http(), "CVE-1999-0001", ttl=0.0)
    assert part.poc_count == 0
    assert part.signals == []


def test_poc_repos_never_fetches_repo_content(
    make_http: Callable[..., HttpClient], feeds: FakeFeeds
) -> None:
    # routed through the allow-listed HttpClient: only the metadata JSON path is legal
    poc_in_github(make_http(), "CVE-2024-6387", ttl=0.0)
    (call,) = feeds.calls
    assert call == (
        "raw.githubusercontent.com",
        "/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-6387.json",
    )


# --------------------------------------------------------------------------- EPSS / GHSA
def test_epss_trend_parsing() -> None:
    trends = parse_epss_trends(load_json("epss_timeseries.json"))
    assert trends["CVE-2024-6387"] == [
        ("2026-09-08", 0.99506),
        ("2026-09-20", 0.99506),
        ("2026-10-09", 0.99506),
    ]
    assert trends["CVE-2021-3156"][-1] == ("2026-10-09", 0.92)


def test_epss_trends_batched(make_http: Callable[..., HttpClient]) -> None:
    out = epss_trends(make_http(), ["CVE-2024-6387", "CVE-2021-3156"])
    assert set(out) == {"CVE-2024-6387", "CVE-2021-3156"}


def test_ghsa_parses_advisories(make_http: Callable[..., HttpClient]) -> None:
    part = ghsa(make_http(), "CVE-2024-6387", ttl=0.0, now=NOW)
    assert part.advisories == []  # fixture returns an empty list; no crash, no refs
    assert part.refs == []
