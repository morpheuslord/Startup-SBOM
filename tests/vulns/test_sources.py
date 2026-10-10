"""Arch tracker, opt-in NVD, and orchestration (source selection, coverage limitations)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

import startup_sbom.vulns.nvd as nvd_mod
from startup_sbom.context import ScanContext
from startup_sbom.models import Confidence, PackageType, Severity, VulnStatus
from startup_sbom.net import HttpClient
from startup_sbom.vulns import ArchTrackerSource, NvdSource, match_vulnerabilities
from startup_sbom.vulns.arch import STALE_NOTE
from startup_sbom.vulns.nvd import cpe_match_applies, parse_cpe
from vulns.helpers import DATA, FakeOsv, Router, pkg

MakeHttp = Callable[..., HttpClient]
MakeCtx = Callable[..., ScanContext]

ALPM = PackageType.ALPM


def arch_host(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/issues/all.json"
    return httpx.Response(200, content=(DATA / "arch_all.json").read_bytes())


# --------------------------------------------------------------------------- Arch
@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        (
            "glibc",
            "2.37-1",
            {"CVE-2023-25139": VulnStatus.AFFECTED, "CVE-2020-29573": VulnStatus.NOT_AFFECTED},
        ),
        ("glibc", "2.37-2", {"CVE-2020-29573": VulnStatus.NOT_AFFECTED}),
        ("glibc", "2.32-4", {}),  # older than every "affected" bound
        ("openssh", "9.7p1-2", {"CVE-2024-6387": VulnStatus.AFFECTED}),
        ("openssh", "9.7p1-3", {"CVE-2024-6387": VulnStatus.AFFECTED}),
        ("openssh", "9.8p1-1", {}),
        ("sudo", "1.9.16-1", {"CVE-2099-0001": VulnStatus.NO_FIX_AVAILABLE}),
        ("zlib", "1:1.3.1-2", {"AVG-9998": VulnStatus.UNDER_INVESTIGATION}),
        ("zlib", "1.3.1-2", {}),  # epoch 0 < 1
    ],
)
def test_arch_matching(
    make_http: MakeHttp, vctx: MakeCtx, name: str, version: str, expected: dict[str, VulnStatus]
) -> None:
    ctx = vctx(os_id="arch")
    src = ArchTrackerSource(make_http(Router(security_archlinux_org=arch_host)))
    vulns = src.match(ctx, [pkg(name, version, ALPM)])
    assert {v.id: v.status for v in vulns} == expected
    assert STALE_NOTE in ctx.limitations
    assert all(v.match_confidence is Confidence.MEDIUM for v in vulns)


def test_arch_details(make_http: MakeHttp, vctx: MakeCtx) -> None:
    src = ArchTrackerSource(make_http(Router(security_archlinux_org=arch_host)))
    (v,) = src.match(vctx(), [pkg("openssh", "9.7p1-2", ALPM)])
    assert v.advisories == ["ASA-202407-1", "AVG-2855"]
    assert v.fixed_versions == ["9.8p1-1"]
    assert v.severity is Severity.HIGH
    assert v.sources == ["arch"]
    assert v.summary == "authentication bypass in openssh"
    assert (
        v.match_reason
        == "arch:AVG-2855 package=openssh affected=9.7p1-2 fixed=9.8p1-1 version=9.7p1-2"
    )


def test_arch_enabled_automatically_and_lib32(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    router = Router(security_archlinux_org=arch_host, api_osv_dev=fake_osv)
    ctx = vctx(os_id="arch")  # default sources = ("osv",)
    vulns = match_vulnerabilities(ctx, [pkg("lib32-glibc", "2.37-1", ALPM)], make_http(router))
    assert [v.id for v in vulns] == ["CVE-2020-29573", "CVE-2023-25139"]
    assert fake_osv.batches == []  # OSV has nothing for alpm


# --------------------------------------------------------------------------- NVD
NVD_DOC: dict[str, Any] = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-6387",
                "published": "2024-07-01T13:15:01.997",
                "lastModified": "2025-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "A signal handler race condition."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "secalert@redhat.com",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.1,
                            },
                        }
                    ]
                },
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-364"}]}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "8.5",
                                        "versionEndExcluding": "9.8",
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "references": [{"url": "https://www.openssh.com/txt/release-9.8"}],
            }
        },
        {
            "cve": {
                "id": "CVE-2006-5051",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "4.4",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        },
    ],
}


def test_nvd_opt_in_key_in_header_only(make_http: MakeHttp, vctx: MakeCtx) -> None:
    seen: list[httpx.Request] = []

    def nvd(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=json.dumps(NVD_DOC).encode())

    sleeps: list[float] = []
    p = pkg(
        "openssh",
        "9.6p1",
        PackageType.GENERIC,
        cpes=["cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"],
    )
    src = NvdSource(make_http(Router(services_nvd_nist_gov=nvd)), "SECRET-KEY", sleep=sleeps.append)
    vulns = src.match(vctx(), [p])
    assert [v.id for v in vulns] == ["CVE-2024-6387"]
    v = vulns[0]
    assert v.match_confidence is Confidence.LOW
    assert v.fixed_versions == ["9.8"]
    assert v.cwes == ["CWE-364"]
    assert v.severity is Severity.HIGH
    assert seen[0].headers["apiKey"] == "SECRET-KEY"
    assert "SECRET" not in str(seen[0].url)
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh" in str(seen[0].url)
    assert sleeps == [0.7]
    assert "SECRET" not in repr(src)


def test_nvd_not_used_unless_selected(make_http: MakeHttp, vctx: MakeCtx) -> None:
    router = Router()
    p = pkg("x", "1.0", PackageType.GENERIC, cpes=["cpe:2.3:a:v:x:1.0:*:*:*:*:*:*:*"])
    ctx = vctx()
    assert match_vulnerabilities(ctx, [p], make_http(router)) == []
    assert router.requests == []
    assert any("1 generic packages" in m for m in ctx.limitations)


def test_nvd_fallback_only_for_uncovered(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx, monkeypatch: pytest.MonkeyPatch
) -> None:
    nvd_calls: list[str] = []

    def nvd(request: httpx.Request) -> httpx.Response:
        nvd_calls.append(str(request.url))
        return httpx.Response(200, content=json.dumps(NVD_DOC).encode())

    router = Router(api_osv_dev=fake_osv, services_nvd_nist_gov=nvd)
    deb = pkg(
        "openssh-server",
        "1:9.6p1-1",
        source="openssh",
        cpes=["cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"],
    )
    gen = pkg(
        "openssh",
        "9.6p1",
        PackageType.GENERIC,
        cpes=["cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"],
    )
    ctx = vctx("Debian:12", vuln_sources=("osv", "nvd"))
    src_sleep: list[float] = []
    monkeypatch.setattr(nvd_mod.time, "sleep", src_sleep.append)
    vulns = match_vulnerabilities(ctx, [deb, gen], make_http(router))
    assert len(nvd_calls) == 1  # only the generic package went to NVD
    assert [(v.package_name, v.id) for v in vulns] == [("openssh", "CVE-2024-6387")]
    assert src_sleep  # paced without a key
    assert src_sleep[0] == pytest.approx(6.5)


@pytest.mark.parametrize(
    ("match", "version", "expected"),
    [
        ({"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.2:*:*:*:*:*:*:*"}, "1.2", True),
        ({"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.2:*:*:*:*:*:*:*"}, "1.3", False),
        ({"vulnerable": False, "criteria": "cpe:2.3:a:v:p:1.2:*:*:*:*:*:*:*"}, "1.2", False),
        ({"vulnerable": True, "criteria": "cpe:2.3:a:other:p:1.2:*:*:*:*:*:*:*"}, "1.2", False),
        (
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                "versionStartExcluding": "1.0",
                "versionEndIncluding": "2.0",
            },
            "2.0",
            True,
        ),
        (
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                "versionStartExcluding": "1.0",
            },
            "1.0",
            False,
        ),
        ({"vulnerable": True, "criteria": "cpe:2.3:a:v:p:-:*:*:*:*:*:*:*"}, "1.0", False),
    ],
)
def test_cpe_match_applies(match: dict[str, Any], version: str, expected: bool) -> None:
    cpe = parse_cpe("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe_match_applies(match, cpe, version) is expected


def test_parse_cpe_escapes() -> None:
    cpe = parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe["product"] == r"prod\:uct"
    assert cpe["version"] == "1.0"
    assert parse_cpe("cpe:/a:old:format") is None


# --------------------------------------------------------------------------- coverage
@pytest.mark.parametrize(
    ("os_id", "label"),
    [
        ("fedora", "Fedora"),
        ("amzn", "Amazon Linux"),
        ("ol", "Oracle Linux"),
        ("photon", "Photon OS"),
    ],
)
def test_unsupported_distro_limitation(
    make_http: MakeHttp, vctx: MakeCtx, os_id: str, label: str
) -> None:
    router = Router()
    ctx = vctx(os_id=os_id)
    p = pkg("openssl-libs", "1:3.0.7-24.fc40", PackageType.RPM, source="openssl")
    assert match_vulnerabilities(ctx, [p], make_http(router)) == []
    assert router.requests == []
    assert any(f"{label} is not covered by OSV.dev" in m for m in ctx.limitations)


def test_unknown_distro_limitation(make_http: MakeHttp, vctx: MakeCtx) -> None:
    ctx = vctx(os_id="unknown")
    assert match_vulnerabilities(ctx, [pkg("bash", "5.2-1")], make_http(Router())) == []
    assert any("1 deb packages" in m and "not covered" in m for m in ctx.limitations)


def test_no_sources_and_unknown_source(make_http: MakeHttp, vctx: MakeCtx) -> None:
    ctx = vctx("Debian:12", vuln_sources=())
    assert match_vulnerabilities(ctx, [pkg("bash", "5.2-1")], make_http(Router())) == []
    assert ctx.limitations == [
        "vulnerability matching disabled (no vulnerability sources selected)"
    ]
    ctx = vctx("Debian:12", vuln_sources=("bogus",))
    match_vulnerabilities(ctx, [pkg("bash", "5.2-1")], make_http(Router()))
    assert ctx.warnings == ["unknown vulnerability source ignored: bogus"]


def test_arch_offline_without_cache(make_http: MakeHttp, vctx: MakeCtx) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network used offline")

    ctx = vctx(os_id="arch", offline=True)
    assert (
        match_vulnerabilities(ctx, [pkg("glibc", "2.37-1", ALPM)], make_http(boom, offline=True))
        == []
    )
    assert any(m.startswith("offline: no cached arch vulnerability data") for m in ctx.limitations)
