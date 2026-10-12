"""OSV source: query planning, batching, pagination, hydration, normalisation."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from startup_sbom.context import ScanContext
from startup_sbom.models import Confidence, OSInfo, PackageType, Severity, VulnStatus
from startup_sbom.net import HttpClient
from startup_sbom.vulns import match_vulnerabilities
from startup_sbom.vulns.normalize import parse_cvss
from startup_sbom.vulns.osv import (
    OsvQuery,
    OsvSource,
    ecosystem_matches,
    plan_queries,
    query_ecosystem,
    refine_ecosystem,
)
from vulns.helpers import FakeOsv, mkrec, pkg

MakeHttp = Callable[..., HttpClient]
MakeCtx = Callable[..., ScanContext]


def _queries(fake: FakeOsv) -> list[tuple[str, str, str]]:
    return [
        (q["package"]["ecosystem"], q["package"]["name"], q["version"])
        for batch in fake.batches
        for q in batch
    ]


# --------------------------------------------------------------------------- Debian
def test_debian_queries_source_and_merges_dsa_with_debian_cve(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    ver = "3.0.11-1~deb12u2"
    fake_osv.add(
        "Debian:12", "openssl", ver, "DEBIAN-CVE-2024-6119", "DSA-5764-1", "DEBIAN-CVE-2023-5678"
    )
    packages = [
        pkg("libssl3", ver, source="openssl", source_version=ver),
        pkg("openssl", ver, source="openssl", source_version=ver),
    ]
    ctx = vctx("Debian:12")
    vulns = match_vulnerabilities(ctx, packages, make_http(fake_osv))

    # one source query covers both binaries; the binary name is never queried
    assert _queries(fake_osv) == [("Debian:12", "openssl", ver)]
    assert [(v.package_name, v.id) for v in vulns] == [
        ("libssl3", "CVE-2023-5678"),
        ("libssl3", "CVE-2024-6119"),
        ("openssl", "CVE-2023-5678"),
        ("openssl", "CVE-2024-6119"),
    ]
    v = next(v for v in vulns if v.id == "CVE-2024-6119" and v.package_name == "libssl3")
    assert v.advisories == ["DEBIAN-CVE-2024-6119", "DSA-5764-1"]
    assert v.sources == ["osv"]
    assert v.fixed_versions == ["3.0.14-1~deb12u2"]
    assert v.status is VulnStatus.AFFECTED
    assert v.installed_version == ver
    assert v.severity is Severity.HIGH
    assert v.cvss[0].version == "3.1"
    assert v.cvss[0].base_score == 7.5
    assert v.summary is not None
    assert v.summary.startswith("Issue summary")  # per-CVE text, not the DSA's
    assert v.published == "2024-09-03T00:00:00Z"
    assert v.match_reason == f"osv:Debian:12 source=openssl version={ver}"
    assert v.match_confidence is Confidence.HIGH
    assert ctx.limitations == []


def test_binnmu_uses_source_version(vctx: MakeCtx) -> None:
    p = pkg("libfoo1", "1.0-1+b1", source="foo", source_version="1.0-1")
    assert list(plan_queries(vctx("Debian:12"), [p])) == [OsvQuery("Debian:12", "foo", "1.0-1")]


@pytest.mark.parametrize(
    ("version", "epoch", "ptype", "expected"),
    [
        ("1:9.2p1-2+deb12u2", None, PackageType.DEB, "1:9.2p1-2+deb12u2"),
        ("9.2p1-2+deb12u2", 1, PackageType.DEB, "1:9.2p1-2+deb12u2"),
        ("0:1.0-1", None, PackageType.RPM, "1.0-1"),
        ("3.0.7-24.el9", 1, PackageType.RPM, "1:3.0.7-24.el9"),
    ],
)
def test_epoch_is_sent(
    vctx: MakeCtx, version: str, epoch: int | None, ptype: PackageType, expected: str
) -> None:
    eco = "Debian:12" if ptype is PackageType.DEB else "Rocky Linux:9"
    p = pkg("openssh", version, ptype, epoch=epoch)
    assert [q.version for q in plan_queries(vctx(eco), [p])] == [expected]


def test_rpm_source_epoch_comes_from_binary_header(vctx: MakeCtx) -> None:
    p = pkg(
        "openssl-libs",
        "1:3.0.7-24.el9",
        PackageType.RPM,
        source="openssl",
        source_version="3.0.7-24.el9",
        epoch=1,
    )
    assert sorted(plan_queries(vctx("AlmaLinux:9"), [p])) == [
        OsvQuery("AlmaLinux:9", "openssl", "1:3.0.7-24.el9"),
        OsvQuery("AlmaLinux:9", "openssl-libs", "1:3.0.7-24.el9"),
    ]


def test_wrong_type_ecosystem_not_used(vctx: MakeCtx) -> None:
    ctx = vctx("Debian:12")
    assert plan_queries(ctx, [pkg("musl", "1.2.4-r2", PackageType.APK)]) == {}


# --------------------------------------------------------------------------- RPM families
def test_rpm_queries_source_and_binary_and_dedupes(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    ver = "1:3.0.7-24.el9"
    fake_osv.add("AlmaLinux:9", "openssl", ver, "ALSA-2024:0310")
    fake_osv.add("AlmaLinux:9", "openssl-libs", ver, "ALSA-2024:0310")
    p = pkg("openssl-libs", ver, PackageType.RPM, source="openssl", source_version="3.0.7-24.el9")
    vulns = match_vulnerabilities(vctx("AlmaLinux:9", os_id="almalinux"), [p], make_http(fake_osv))
    assert sorted(_queries(fake_osv)) == [
        ("AlmaLinux:9", "openssl", ver),
        ("AlmaLinux:9", "openssl-libs", ver),
    ]
    assert len(vulns) == 1
    v = vulns[0]
    assert v.id == "CVE-2023-5363"
    assert v.advisories == ["ALSA-2024:0310"]
    assert v.fixed_versions == ["1:3.0.7-25.el9_3"]
    assert v.severity is Severity.MEDIUM  # "Moderate: ..." summary, no vector in ALSA
    assert fake_osv.gets.count("ALSA-2024:0310") == 1  # hydrated once


def test_rhel_streams_queried_by_base_and_filtered_locally(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    ver = "1:3.0.7-24.el9"
    for rec in (
        mkrec(
            "RHSA-2099:0008",
            "Red Hat:enterprise_linux:8::baseos",
            "openssl-libs",
            [{"introduced": "0"}, {"fixed": "1:3.0.9-1.el8"}],
            upstream=["CVE-2099-0008"],
        ),
        mkrec(
            "RHSA-2099:0009",
            "Red Hat:enterprise_linux:9::baseos",
            "openssl-libs",
            [{"introduced": "0"}, {"fixed": "1:3.0.1-1.el9"}],  # installed is newer
            upstream=["CVE-2099-0009"],
        ),
    ):
        records[rec["id"]] = rec
    fake_osv.add(
        "Red Hat",
        "openssl-libs",
        ver,
        "RHSA-2024:6783",
        "RHSA-2024:0310",
        "RHSA-2099:0008",
        "RHSA-2099:0009",
    )
    fake_osv.add("Red Hat", "openssl", ver, "RHSA-2024:6783")
    p = pkg("openssl-libs", ver, PackageType.RPM, source="openssl", source_version="3.0.7-24.el9")
    ctx = vctx(
        "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream", os_id="rhel"
    )
    vulns = match_vulnerabilities(ctx, [p], make_http(fake_osv))
    assert {q[0] for q in _queries(fake_osv)} == {"Red Hat"}
    assert len(_queries(fake_osv)) == 2  # both streams collapse onto one base query per name
    assert [v.id for v in vulns] == ["CVE-2023-5363", "CVE-2024-6119"]
    by_id = {v.id: v for v in vulns}
    assert by_id["CVE-2024-6119"].fixed_versions == ["1:3.0.7-28.el9_4"]
    assert by_id["CVE-2024-6119"].advisories == ["RHSA-2024:6783"]


def test_suse_module_filtering(fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx) -> None:
    ver = "3.1.4-150600.5.7.1"
    fake_osv.add("SUSE", "openssl-3", ver, "SUSE-SU-2024:3106-1")
    p = pkg("libopenssl3", ver, PackageType.RPM, source="openssl-3", source_version=ver)
    ctx = vctx("SUSE:Linux Enterprise Server 15 SP6", os_id="sles")
    vulns = match_vulnerabilities(ctx, [p], make_http(fake_osv))
    assert ("SUSE", "libopenssl3", ver) in _queries(fake_osv)
    assert [v.id for v in vulns] == ["CVE-2024-6119"]
    assert vulns[0].fixed_versions == ["3.1.4-150600.5.15.1"]
    assert vulns[0].match_reason == (
        f"osv:SUSE:Linux Enterprise Server 15 SP6 source=openssl-3 version={ver}"
    )


@pytest.mark.parametrize(
    ("requested", "actual", "expected"),
    [
        ("Debian:12", "Debian:12", True),
        ("Debian:12", "Debian:13", False),
        ("Alpine:v3.19", "Alpine:v3.1", False),
        ("Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream", True),
        ("Red Hat:enterprise_linux:9", "Red Hat:enterprise_linux:8::baseos", False),
        ("Red Hat:enterprise_linux:9", "Red Hat:enterprise_linux:90::baseos", False),
        ("Red Hat:enterprise_linux:10.1", "Red Hat:enterprise_linux:10.1", True),
        ("Red Hat:enterprise_linux:10.1", "Red Hat:enterprise_linux:10::fastdatapath", True),
        ("Red Hat:enterprise_linux:10.1", "Red Hat:enterprise_linux:10.0", False),
        ("Red Hat:enterprise_linux:10", "Red Hat:enterprise_linux:10.2", True),
        (
            "SUSE:Linux Enterprise Server 15 SP6",
            "SUSE:Linux Enterprise Module for Basesystem 15 SP6",
            True,
        ),
        ("SUSE:Linux Enterprise Server 15 SP6", "SUSE:Linux Enterprise Server 15 SP6-LTSS", True),
        ("SUSE:Linux Enterprise Server 15 SP6", "SUSE:Linux Enterprise Server 15 SP5", False),
        ("SUSE:Linux Enterprise Server 15", "SUSE:Linux Enterprise Server 15 SP6", False),
        ("SUSE:Linux Enterprise Server 15 SP6", "openSUSE:Leap 15.6", False),
        ("SUSE:Linux Micro 6.1", "SUSE:Linux Micro 6.1", True),
        ("Ubuntu:*", "Ubuntu:22.04:LTS", True),
    ],
)
def test_ecosystem_matches(requested: str, actual: str, expected: bool) -> None:
    assert ecosystem_matches(requested, actual) is expected


@pytest.mark.parametrize(
    ("requested", "sent"),
    [
        ("Debian:12", "Debian:12"),
        ("Ubuntu:22.04:LTS", "Ubuntu:22.04:LTS"),
        ("Red Hat:enterprise_linux:9::baseos", "Red Hat"),
        ("SUSE:Linux Enterprise Server 15 SP6", "SUSE"),
        ("SUSE:Linux Micro 6.1", "SUSE:Linux Micro 6.1"),
        ("openSUSE:Leap 15.6", "openSUSE:Leap 15.6"),
    ],
)
def test_query_ecosystem(requested: str, sent: str) -> None:
    assert query_ecosystem(requested) == sent


def test_vendor_without_epoch_compared_without_epoch(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    rec = mkrec(
        "RHSA-2099:0100",
        "Red Hat:enterprise_linux:9::baseos",
        "openssl",
        [{"introduced": "0"}, {"fixed": "3.0.7-30.el9"}],
        upstream=["CVE-2099-0100"],
    )
    records[rec["id"]] = rec
    fake_osv.add("Red Hat", "openssl", "1:3.0.7-24.el9", rec["id"])
    p = pkg("openssl", "1:3.0.7-24.el9", PackageType.RPM)
    vulns = match_vulnerabilities(vctx("Red Hat:enterprise_linux:9"), [p], make_http(fake_osv))
    assert [v.id for v in vulns] == ["CVE-2099-0100"]
    assert vulns[0].match_confidence is Confidence.MEDIUM
    assert vulns[0].fixed_versions == ["3.0.7-30.el9"]


# --------------------------------------------------------------------------- Ubuntu / Alpine
def test_ubuntu_cvss_beats_distro_priority_and_related_usns(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    ver = "3.0.2-0ubuntu1.10"
    fake_osv.add("Ubuntu:22.04:LTS", "openssl", ver, "UBUNTU-CVE-2023-5678")
    p = pkg("libssl3", ver, source="openssl", source_version=ver)
    vulns = match_vulnerabilities(
        vctx("Ubuntu:22.04:LTS", os_id="ubuntu"), [p], make_http(fake_osv)
    )
    v = vulns[0]
    assert v.id == "CVE-2023-5678"
    assert v.fixed_versions == ["3.0.2-0ubuntu1.14"]  # only the 22.04 entry, not Pro 16.04
    assert v.severity is Severity.MEDIUM  # CVSS 5.3 preferred over Ubuntu "low"
    assert "USN-6622-1" in v.advisories
    assert "UBUNTU-CVE-2023-5678" in v.advisories


def test_alpine_origin(fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx) -> None:
    fake_osv.add("Alpine:v3.19", "openssl", "3.1.4-r0", "ALPINE-CVE-2023-5678")
    p = pkg("libcrypto3", "3.1.4-r0", PackageType.APK, source="openssl")
    vulns = match_vulnerabilities(vctx("Alpine:v3.19", os_id="alpine"), [p], make_http(fake_osv))
    assert _queries(fake_osv) == [("Alpine:v3.19", "openssl", "3.1.4-r0")]
    assert vulns[0].fixed_versions == ["3.1.4-r1"]


# --------------------------------------------------------------------------- statuses
def test_distro_status_will_not_fix_and_no_fix(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    eol = mkrec(
        "DEBIAN-CVE-2099-0001",
        "Debian:12",
        "foo",
        [{"introduced": "0"}],
        upstream=["CVE-2099-0001"],
        ecosystem_specific={"urgency": "end-of-life"},
    )
    nofix = mkrec(
        "DEBIAN-CVE-2099-0002",
        "Debian:12",
        "foo",
        [{"introduced": "0"}],
        upstream=["CVE-2099-0002"],
        ecosystem_specific={"urgency": "unimportant"},
    )
    records.update({eol["id"]: eol, nofix["id"]: nofix})
    fake_osv.add("Debian:12", "foo", "1.0-1", eol["id"], nofix["id"])
    vulns = match_vulnerabilities(vctx("Debian:12"), [pkg("foo", "1.0-1")], make_http(fake_osv))
    status = {v.id: v.status for v in vulns}
    assert status == {
        "CVE-2099-0001": VulnStatus.WILL_NOT_FIX,
        "CVE-2099-0002": VulnStatus.NO_FIX_AVAILABLE,
    }
    sev = {v.id: v.severity for v in vulns}
    assert sev["CVE-2099-0002"] is Severity.LOW  # Debian "unimportant", no CVSS


def test_cvss_v4_preferred_and_cwe_and_reference_cap(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    rec = mkrec(
        "GHSA-aaaa-bbbb-cccc",
        "npm",
        "@scope/lib",
        [{"introduced": "0"}, {"fixed": "2.0.0"}],
        aliases=["CVE-2099-1234"],
        summary="x" * 500,
        severity=[
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"},
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {"type": "CVSS_V3", "score": "CVSS:3.1/garbage"},
        ],
        database_specific={"cwe_ids": ["CWE-94", "CWE-79", "cwe-79"]},
        references=[{"type": "WEB", "url": f"https://example.org/{i}"} for i in range(15)],
    )
    records[rec["id"]] = rec
    fake_osv.add("npm", "@scope/lib", "1.0.0", rec["id"])
    p = pkg("lib", "1.0.0", PackageType.NPM, purl="pkg:npm/%40scope/lib@1.0.0")
    vulns = match_vulnerabilities(vctx(), [p], make_http(fake_osv))
    v = vulns[0]
    assert v.id == "CVE-2099-1234"
    assert v.aliases == []
    assert v.advisories == ["GHSA-aaaa-bbbb-cccc"]
    assert v.severity is Severity.CRITICAL
    assert v.best_cvss is not None
    assert v.best_cvss.version == "4.0"
    assert [c.version for c in v.cvss] == ["4.0", "3.1"]
    assert v.cwes == ["CWE-79", "CWE-94"]
    assert len(v.references) == 10
    assert v.summary is not None
    assert len(v.summary) == 300
    assert v.summary.endswith("…")


@pytest.mark.parametrize(
    ("kind", "vector", "version", "score"),
    [
        ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", 9.8),
        ("CVSS_V3", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "3.0", 7.5),
        ("CVSS_V4", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "4.0", 8.5),
        ("CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0", 7.5),
    ],
)
def test_parse_cvss(kind: str, vector: str, version: str, score: float) -> None:
    parsed = parse_cvss(kind, vector, "NVD")
    assert parsed is not None
    assert (parsed.version, parsed.base_score, parsed.source) == (version, score, "NVD")
    assert parsed.severity is Severity.from_score(score)


@pytest.mark.parametrize("vector", ["", "CVSS:3.1/AV:X", "CVSS:4.0/AV:N", "nonsense", "AV:Q"])
def test_parse_cvss_rejects_garbage(vector: str) -> None:
    assert parse_cvss("CVSS_V3", vector) is None


# --------------------------------------------------------------------------- language ecosystems
def test_language_names(vctx: MakeCtx) -> None:
    packages = [
        pkg("Jinja2", "2.10", PackageType.PYPI),
        pkg("zope.interface", "5.0", PackageType.PYPI),
        pkg("lib", "1.0.0", PackageType.NPM, purl="pkg:npm/%40scope/lib@1.0.0"),
        pkg("net", "v0.17.0", PackageType.GOLANG, purl="pkg:golang/golang.org/x/net@v0.17.0"),
        pkg(
            "log4j-core",
            "2.14.1",
            PackageType.MAVEN,
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        ),
        pkg("serde", "1.0.0", PackageType.CARGO),
        pkg("weird", "(devel)", PackageType.GOLANG),
    ]
    assert sorted(plan_queries(vctx("Debian:12"), packages)) == [
        OsvQuery("Go", "golang.org/x/net", "0.17.0"),
        OsvQuery("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        OsvQuery("PyPI", "jinja2", "2.10"),
        OsvQuery("PyPI", "zope-interface", "5.0"),
        OsvQuery("crates.io", "serde", "1.0.0"),
        OsvQuery("npm", "@scope/lib", "1.0.0"),
    ]


def test_pypi_and_pagination(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    pysec = mkrec(
        "PYSEC-2026-1473",
        "PyPI",
        "jinja2",
        [{"introduced": "0"}, {"fixed": "3.1.3"}],
        aliases=["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95"],
    )
    records[pysec["id"]] = pysec
    fake_osv.page_size = 1
    fake_osv.add("PyPI", "jinja2", "2.10", "GHSA-h5c8-rqwp-cp95", "PYSEC-2026-1473")
    vulns = match_vulnerabilities(
        vctx(), [pkg("Jinja2", "2.10", PackageType.PYPI)], make_http(fake_osv)
    )
    assert len(fake_osv.batches) == 2
    assert fake_osv.batches[1][0]["page_token"] == "1"  # noqa: S105
    assert len(vulns) == 1
    v = vulns[0]
    assert v.id == "CVE-2024-22195"
    assert v.advisories == ["GHSA-h5c8-rqwp-cp95", "PYSEC-2026-1473"]
    assert v.cwes == ["CWE-79"]
    assert v.fixed_versions == ["3.1.3"]
    assert v.severity is Severity.MEDIUM
    assert v.match_reason == "osv:PyPI package=jinja2 version=2.10"


def test_querybatch_split_at_1000(fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx) -> None:
    packages = [pkg(f"p{i}", "1.0", PackageType.PYPI) for i in range(1500)]
    assert match_vulnerabilities(vctx(), packages, make_http(fake_osv)) == []
    assert [len(b) for b in fake_osv.batches] == [1000, 500]


# --------------------------------------------------------------------------- caching
def test_hydration_cached_by_id_and_modified(fake_osv: FakeOsv, make_http: MakeHttp) -> None:
    src = OsvSource(make_http(fake_osv))
    vid = "GHSA-h5c8-rqwp-cp95"
    recs, failed = src.hydrate({vid: "m1"})
    assert vid in recs
    assert not failed
    src.hydrate({vid: "m1"})
    assert fake_osv.gets == [vid]
    src.hydrate({vid: "m2"})  # record changed upstream -> refetched
    assert fake_osv.gets == [vid, vid]


def test_second_scan_served_from_cache(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    fake_osv.add("PyPI", "jinja2", "2.10", "GHSA-h5c8-rqwp-cp95")
    p = [pkg("jinja2", "2.10", PackageType.PYPI)]
    first = match_vulnerabilities(vctx(), p, make_http(fake_osv))
    calls = (len(fake_osv.batches), len(fake_osv.gets))
    second = match_vulnerabilities(vctx(), p, make_http(fake_osv))
    assert first == second
    assert (len(fake_osv.batches), len(fake_osv.gets)) == calls == (1, 1)


def test_offline_uses_cache(fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx) -> None:
    fake_osv.add("Debian:12", "openssl", "3.0.11-1~deb12u2", "DSA-5764-1")
    p = [pkg("openssl", "3.0.11-1~deb12u2")]
    online = match_vulnerabilities(vctx("Debian:12"), p, make_http(fake_osv))

    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network used in offline mode")

    ctx = vctx("Debian:12", offline=True)
    offline = match_vulnerabilities(ctx, p, make_http(boom, offline=True))
    assert offline == online
    assert ctx.limitations == []


def test_offline_without_cache_records_limitation(make_http: MakeHttp, vctx: MakeCtx) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network used in offline mode")

    ctx = vctx("Debian:12", offline=True)
    assert (
        match_vulnerabilities(ctx, [pkg("openssl", "3.0.11-1")], make_http(boom, offline=True))
        == []
    )
    assert any(m.startswith("offline: no cached vulnerability data") for m in ctx.limitations)


# --------------------------------------------------------------------------- failures
def test_network_failure_is_a_limitation(make_http: MakeHttp, vctx: MakeCtx) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable", request=request)

    ctx = vctx("Debian:12")
    assert match_vulnerabilities(ctx, [pkg("openssl", "3.0.11-1")], make_http(down)) == []
    assert ctx.warnings
    assert any("osv: 1 of 1 package queries failed" in m for m in ctx.limitations)


def test_missing_record_is_a_limitation_others_kept(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    fake_osv.add("Debian:12", "openssl", "3.0.11-1~deb12u2", "DSA-5764-1", "DSA-0000-1")
    ctx = vctx("Debian:12")
    vulns = match_vulnerabilities(ctx, [pkg("openssl", "3.0.11-1~deb12u2")], make_http(fake_osv))
    assert [v.id for v in vulns] == ["CVE-2024-6119"]
    assert any("could not be retrieved" in m for m in ctx.limitations)


def test_malformed_batch_response(make_http: MakeHttp, vctx: MakeCtx) -> None:
    def bad(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps({"results": []}).encode())

    ctx = vctx("Debian:12")
    assert match_vulnerabilities(ctx, [pkg("openssl", "3.0.11-1")], make_http(bad)) == []
    assert ctx.limitations


def test_deterministic_output(fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx) -> None:
    ver = "3.0.11-1~deb12u2"
    fake_osv.add(
        "Debian:12", "openssl", ver, "DSA-5764-1", "DEBIAN-CVE-2023-5678", "DEBIAN-CVE-2024-6119"
    )
    packages = [pkg("openssl", ver), pkg("libssl3", ver, source="openssl")]
    a = match_vulnerabilities(vctx("Debian:12"), packages, make_http(fake_osv))
    b = match_vulnerabilities(vctx("Debian:12"), list(reversed(packages)), make_http(fake_osv))
    assert [v.model_dump() for v in a] == [v.model_dump() for v in b]


# --------------------------------------------------------------------------- bare vendor ecosystems
@pytest.mark.parametrize(
    ("eco", "os_id", "version_id", "pretty", "expected"),
    [
        ("Red Hat", "rhel", "9.4", None, "Red Hat:enterprise_linux:9"),
        ("Red Hat", "rhel", "8", None, "Red Hat:enterprise_linux:8"),
        ("Red Hat", "rhel", "10.1", None, "Red Hat:enterprise_linux:10.1"),
        ("Red Hat", "rhel", None, None, "Red Hat"),
        (
            "SUSE",
            "sles",
            "15.6",
            "SUSE Linux Enterprise Server 15 SP6",
            "SUSE:Linux Enterprise Server 15 SP6",
        ),
        ("SUSE", "sles", "15.5", None, "SUSE:Linux Enterprise Server 15 SP5"),
        ("SUSE", "sles", "16.0", None, "SUSE:Linux Enterprise Server 16.0"),
        ("SUSE", "sl-micro", "6.1", "SUSE Linux Micro 6.1", "SUSE:Linux Micro 6.1"),
        ("SUSE", "sles", None, None, "SUSE"),
        ("Debian:12", "debian", "12", None, "Debian:12"),
    ],
)
def test_refine_ecosystem(
    eco: str, os_id: str, version_id: str | None, pretty: str | None, expected: str
) -> None:
    os = OSInfo(id=os_id, version_id=version_id, pretty_name=pretty)
    assert refine_ecosystem(os, eco) == expected


def test_bare_red_hat_uses_os_release_major(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    rhel8 = mkrec(
        "RHSA-2099:0008",
        "Red Hat:enterprise_linux:8::baseos",
        "openssl",
        [{"introduced": "0"}, {"fixed": "1:3.0.9-1.el8"}],
        upstream=["CVE-2099-0008"],
    )
    records[rhel8["id"]] = rhel8
    ver = "1:3.0.7-24.el9"
    fake_osv.add("Red Hat", "openssl", ver, "RHSA-2024:6783", rhel8["id"])
    ctx = vctx("Red Hat")
    ctx.os = OSInfo(id="rhel", version_id="9.4", vuln_ecosystems=["Red Hat"])
    vulns = match_vulnerabilities(ctx, [pkg("openssl", ver, PackageType.RPM)], make_http(fake_osv))
    assert [v.id for v in vulns] == ["CVE-2024-6119"]
    assert vulns[0].match_reason == f"osv:Red Hat:enterprise_linux:9 source=openssl version={ver}"
    assert vulns[0].match_confidence is Confidence.HIGH

    # without a release the vendor-wide filter is used and confidence drops
    ctx = vctx("Red Hat", os_id="rhel")
    vulns = match_vulnerabilities(ctx, [pkg("openssl", ver, PackageType.RPM)], make_http(fake_osv))
    assert {v.id for v in vulns} == {"CVE-2024-6119", "CVE-2099-0008"}
    assert {v.match_confidence for v in vulns} == {Confidence.MEDIUM}
