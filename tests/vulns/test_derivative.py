"""Derivative fallback: rolling Debian derivatives (Kali) matched against Debian testing."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from startup_sbom.context import ScanContext
from startup_sbom.models import Confidence, OSInfo, PackageType, VulnStatus
from startup_sbom.net import HttpClient
from startup_sbom.vulns import match_vulnerabilities
from startup_sbom.vulns.osv import OsvQuery, os_ecosystems, plan_queries
from vulns.helpers import FakeOsv, Router, mkrec, pkg

MakeHttp = Callable[..., HttpClient]
MakeCtx = Callable[..., ScanContext]

KALI = OSInfo(
    id="kali",
    id_like=["debian"],
    name="Kali GNU/Linux",
    pretty_name="Kali GNU/Linux Rolling",
    version_id="2025.3",
    version_codename="kali-rolling",
    family="debian",
    vuln_ecosystems=["Debian:14"],
)


@pytest.fixture
def kctx(vctx: MakeCtx) -> Callable[..., ScanContext]:
    def _make(**options: Any) -> ScanContext:
        ctx = vctx(**options)
        ctx.os = KALI.model_copy(deep=True)
        return ctx

    return _make


def _add(records: dict[str, Any], fake: FakeOsv, name: str, version: str, fixed: str) -> str:
    rec = mkrec(
        f"DEBIAN-CVE-2099-{len(records):04d}",
        "Debian:14",
        name,
        [{"introduced": "0"}, {"fixed": fixed}],
        upstream=[f"CVE-2099-{len(records):04d}"],
    )
    records[rec["id"]] = rec
    fake.add("Debian:14", name, version, rec["id"])
    return f"CVE-2099-{len(records) - 1:04d}"


def test_plan_uses_parent_ecosystem_and_normalised_version(kctx: Callable[..., ScanContext]):
    plain = pkg("bash", "5.2.37-2")
    kali = pkg("libssl3", "3.5.1-1+kali1", source="openssl", source_version="3.5.1-1+kali1")
    tilde = pkg("curl", "8.14.1-2~kali1")
    plan = plan_queries(kctx(), [plain, kali, tilde])
    assert sorted(plan) == [
        OsvQuery("Debian:14", "bash", "5.2.37-2"),
        OsvQuery("Debian:14", "curl", "8.14.1-2~kali1"),  # "~" kept: never more patched
        OsvQuery("Debian:14", "openssl", "3.5.1-1"),
    ]
    targets = {t.package.name: t for ts in plan.values() for t in ts}
    assert all(t.fallback for t in targets.values())
    assert targets["libssl3"].derived_from == "3.5.1-1+kali1"
    assert targets["bash"].derived_from is None
    assert targets["curl"].derived_from is None


def test_fallback_matches_have_reduced_confidence(
    fake_osv: FakeOsv,
    records: dict[str, Any],
    make_http: MakeHttp,
    kctx: Callable[..., ScanContext],
) -> None:
    bash_cve = _add(records, fake_osv, "bash", "5.2.37-2", "5.2.37-3")
    ssl_cve = _add(records, fake_osv, "openssl", "3.5.1-1", "3.5.1-2")
    packages = [
        pkg("bash", "5.2.37-2", purl="pkg:deb/kali/bash@5.2.37-2?arch=amd64"),
        pkg("libssl3", "3.5.1-1+kali1", source="openssl", source_version="3.5.1-1+kali1"),
    ]
    ctx = kctx()
    vulns = match_vulnerabilities(ctx, packages, make_http(fake_osv))
    by_id = {v.id: v for v in vulns}
    assert set(by_id) == {bash_cve, ssl_cve}

    bash = by_id[bash_cve]
    assert bash.match_confidence is Confidence.MEDIUM
    assert bash.match_reason == "osv:Debian:14 source=bash version=5.2.37-2 (derivative fallback)"
    assert bash.status is VulnStatus.AFFECTED
    assert bash.fixed_versions == ["5.2.37-3"]
    assert bash.package == packages[0].id  # package identity (kali purl) untouched

    ssl = by_id[ssl_cve]
    assert ssl.match_confidence is Confidence.LOW  # vendor-modified build
    assert ssl.installed_version == "3.5.1-1+kali1"
    assert ssl.match_reason is not None
    assert "3.5.1-1+kali1 compared as 3.5.1-1" in ssl.match_reason

    assert not any("not assessed" in m for m in ctx.limitations)
    assert ctx.limitations == [
        "Kali GNU/Linux Rolling: 2 deb packages matched against Debian testing"
        " (forky, Debian:14) advisories as a derivative fallback (OSV.dev has no ecosystem"
        " for this distribution); vendor revision suffixes are ignored and confidence is"
        " reduced"
    ]


def test_native_debian_unaffected(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    rec = mkrec(
        "DEBIAN-CVE-2099-9000",
        "Debian:14",
        "bash",
        [{"introduced": "0"}, {"fixed": "5.2.37-3"}],
        upstream=["CVE-2099-9000"],
    )
    records[rec["id"]] = rec
    fake_osv.add("Debian:14", "bash", "5.2.37-2", rec["id"])
    ctx = vctx("Debian:14")
    ctx.os.version_codename = "forky"
    (v,) = match_vulnerabilities(ctx, [pkg("bash", "5.2.37-2")], make_http(fake_osv))
    assert v.match_confidence is Confidence.HIGH
    assert v.match_reason == "osv:Debian:14 source=bash version=5.2.37-2"
    assert ctx.limitations == []
    # a "+kali" looking suffix on Debian itself is never touched
    assert list(plan_queries(ctx, [pkg("x", "1.0-1+kali1")])) == [
        OsvQuery("Debian:14", "x", "1.0-1+kali1")
    ]


def test_fallback_disabled_keeps_old_limitation(
    make_http: MakeHttp, kctx: Callable[..., ScanContext]
) -> None:
    router = Router()
    ctx = kctx(derivative_fallback=False)
    assert os_ecosystems(ctx, PackageType.DEB) == []
    packages = [pkg("bash", "5.2.37-2"), pkg("coreutils", "9.7-3")]
    assert match_vulnerabilities(ctx, packages, make_http(router)) == []
    assert router.requests == []
    assert ctx.limitations == [
        "vulnerabilities not assessed for 2 deb packages: Kali GNU/Linux Rolling is not"
        " covered by OSV.dev (no distro advisory source; NVD CPE matching is available as"
        " an opt-in approximation)"
    ]
