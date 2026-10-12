"""CVE prioritisation and article-candidate ranking."""

from __future__ import annotations

from intel.helpers import make_report, make_threat, make_vuln
from startup_sbom.intel.select import Reference, normalise_url, rank_references, select_cves
from startup_sbom.models import KEVInfo, SSVCDecision


# --------------------------------------------------------------------------- CVEs
def test_priority_order_decision_kev_risk_epss() -> None:
    vulns = [
        make_vuln("CVE-2020-0001", epss=0.9),
        make_vuln("CVE-2020-0002"),
        make_vuln("CVE-2020-0003", kev=KEVInfo(date_added="2024-01-01")),
        make_vuln("CVE-2020-0004"),
        make_vuln("CVE-2020-0005", epss=0.2),
        make_vuln("CVE-2020-0006", epss=0.1),
    ]
    threats = [
        make_threat("CVE-2020-0001", decision=SSVCDecision.TRACK, risk_score=90.0),
        make_threat("CVE-2020-0002", decision=SSVCDecision.ACT, risk_score=10.0),
        make_threat("CVE-2020-0003", decision=SSVCDecision.ATTEND, risk_score=10.0),
        make_threat("CVE-2020-0004", decision=SSVCDecision.ATTEND, risk_score=50.0),
        make_threat("CVE-2020-0005", decision=SSVCDecision.TRACK_STAR, risk_score=20.0),
        make_threat("CVE-2020-0006", decision=SSVCDecision.TRACK_STAR, risk_score=20.0),
    ]
    targets, leftover = select_cves(make_report(vulns, threats), 4)
    # Act > Attend (KEV wins inside Attend) > Track*; risk then EPSS break the remaining ties
    assert [t.cve for t in targets] == [
        "CVE-2020-0002",
        "CVE-2020-0003",
        "CVE-2020-0004",
        "CVE-2020-0005",
    ]
    assert leftover == ["CVE-2020-0006", "CVE-2020-0001"]


def test_dedupes_by_cve_across_packages_and_aliases() -> None:
    vulns = [
        make_vuln("CVE-2021-3156", package="pkg:deb/sudo"),
        make_vuln("CVE-2021-3156", package="pkg:rpm/sudo"),
        make_vuln("USN-4705-1", aliases=["CVE-2021-3156"]),
    ]
    threats = [
        make_threat("CVE-2021-3156", tid="t1", risk_score=50.0),
        make_threat("CVE-2021-3156", tid="t2", risk_score=70.0),
        make_threat("USN-4705-1", tid="t3", risk_score=20.0),
    ]
    targets, leftover = select_cves(make_report(vulns, threats), 10)
    assert [t.cve for t in targets] == ["CVE-2021-3156"]
    assert leftover == []
    assert len(targets[0].vulnerabilities) == 3  # context merged across threats


def test_non_cve_without_alias_is_skipped() -> None:
    vulns = [make_vuln("GHSA-xxxx-yyyy-zzzz")]
    targets, leftover = select_cves(make_report(vulns, [make_threat("GHSA-xxxx-yyyy-zzzz")]), 5)
    assert targets == []
    assert leftover == []


def test_falls_back_to_vulnerabilities_without_threat_stage() -> None:
    vulns = [
        make_vuln("CVE-2020-0001", epss=0.1),
        make_vuln("CVE-2020-0002", kev=KEVInfo(date_added="2024-01-01")),
    ]
    targets, _ = select_cves(make_report(vulns, []), 5)
    assert [t.cve for t in targets] == ["CVE-2020-0002", "CVE-2020-0001"]


def test_selection_is_deterministic() -> None:
    vulns = [make_vuln(f"CVE-2020-{n:04d}") for n in range(1, 8)]
    threats = [make_threat(v.id, risk_score=5.0) for v in vulns]
    report = make_report(vulns, threats)
    first = [t.cve for t in select_cves(report, 5)[0]]
    second = [t.cve for t in select_cves(report, 5)[0]]
    assert first == second == [f"CVE-2020-{n:04d}" for n in range(1, 6)]


# --------------------------------------------------------------------------- articles
def test_rank_references_weights_and_per_host_cap() -> None:
    refs = [
        Reference("https://a.example.org/exploit", "nvd", ("Exploit",)),
        Reference("https://a.example.org/advisory", "nvd", ("Third Party Advisory",)),
        Reference("https://a.example.org/third", "nvd", ("Third Party Advisory",)),
        Reference("https://b.example.org/patch", "nvd", ("Patch",)),
        Reference("https://c.example.org/dead", "nvd", ("Exploit", "Broken Link")),
        Reference("https://github.com/x/poc", "nvd", ("Exploit",)),  # code host: skipped
        Reference("https://www.google.com/search?q=x", "osv"),  # search engine: skipped
        Reference("https://d.example.org/sploit.tar.gz", "nvd", ("Exploit",)),  # binary
    ]
    out = rank_references(refs, 10)
    assert [c.url for c in out] == [
        "https://a.example.org/exploit",
        "https://a.example.org/advisory",
        "https://b.example.org/patch",
    ]  # third a.example.org candidate dropped by the <=2 per host cap
    assert out[0].kind == "exploit"
    assert out[1].kind == "writeup"
    assert out[2].kind == "patch"
    assert out[0].score > out[1].score > out[2].score


def test_rank_references_merges_duplicates_across_origins() -> None:
    refs = [
        Reference("http://x.example.org/post", "cna", ()),
        Reference("https://x.example.org/post/", "nvd", ("Exploit",)),
    ]
    (candidate,) = rank_references(refs, 5)
    assert candidate.url == "https://x.example.org/post"  # https twin, no trailing slash
    assert candidate.origins == ["cna", "nvd"]
    assert candidate.kind == "exploit"


def test_rank_references_mailing_list_kind() -> None:
    (candidate,) = rank_references(
        [Reference("https://seclists.org/fulldisclosure/2021/Jan/79", "nvd", ())], 5
    )
    assert candidate.kind == "mailing-list"


def test_normalise_url() -> None:
    assert normalise_url("http://example.org/a#frag") == "https://example.org/a"
    assert normalise_url("https://Example.ORG/a/") == "https://example.org/a"
    assert normalise_url("ftp://example.org/a") is None
    assert normalise_url("not a url") is None
