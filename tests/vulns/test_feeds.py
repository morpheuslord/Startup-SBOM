"""EPSS (bulk CSV + API fallback), CISA KEV, enrichment and feed management."""

from __future__ import annotations

import gzip
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from startup_sbom.context import ScanContext
from startup_sbom.errors import NetworkError
from startup_sbom.models import PackageType
from startup_sbom.net import HttpClient
from startup_sbom.vulns import feed_status, match_vulnerabilities, update_feeds
from startup_sbom.vulns.epss import (
    API_MAX_CHARS,
    API_MAX_CVES,
    _chunks,
    epss_from_api,
    fetch_epss_csv,
    load_epss,
    parse_epss_csv,
)
from startup_sbom.vulns.kev import load_kev, parse_kev
from vulns.helpers import DATA, FakeOsv, Router, pkg

MakeHttp = Callable[..., HttpClient]
MakeCtx = Callable[..., ScanContext]

CSV = (
    b"#model_version:v2026.06.15,score_date:2026-10-09T12:00:22Z\n"
    b"cve,epss,percentile\n"
    b"CVE-2024-6119,0.01234,0.55000\n"
    b"CVE-2023-5678,0.04459,0.91198\n"
    b"CVE-2021-44228,0.94400,0.99990\n"
    b"CVE-bad,notanumber,0.1\n"
)
TODAY = date(2026, 10, 10)


def epss_host(available: dict[str, bytes]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        name = request.url.path.lstrip("/")
        if name in available:
            return httpx.Response(200, content=available[name])
        if "*" in available and name.startswith("epss_scores-"):
            return httpx.Response(200, content=available["*"])
        return httpx.Response(403, content=b"<Error/>")

    return handler


# --------------------------------------------------------------------------- EPSS
def test_parse_epss_csv_gz_and_header() -> None:
    data = parse_epss_csv(gzip.compress(CSV))
    assert data.score_date == "2026-10-09"
    assert data.model_version == "v2026.06.15"
    assert data.scores["CVE-2021-44228"] == (0.944, 0.9999)
    assert "CVE-bad" not in data.scores
    wanted = parse_epss_csv(CSV, {"CVE-2023-5678"})
    assert wanted.scores == {"CVE-2023-5678": (0.04459, 0.91198)}


def test_parse_epss_rejects_garbage() -> None:
    with pytest.raises(NetworkError):
        parse_epss_csv(b"<html>nope</html>")
    with pytest.raises(NetworkError):
        parse_epss_csv(b"\x1f\x8bnot-gzip")


def test_epss_dated_file_lookback_and_pointer(make_http: MakeHttp) -> None:
    router = Router(
        epss_empiricalsecurity_com=epss_host({"epss_scores-2026-10-09.csv.gz": gzip.compress(CSV)})
    )
    http = make_http(router)
    raw, day = fetch_epss_csv(http, today=TODAY)
    assert day == "2026-10-09"
    paths = [r.url.path for r in router.requests]
    assert paths == ["/epss_scores-2026-10-10.csv.gz", "/epss_scores-2026-10-09.csv.gz"]
    # second call: fresh pointer, served from cache without any request
    raw2, day2 = fetch_epss_csv(http, today=TODAY)
    assert (raw2, day2) == (raw, day)
    assert len(router.requests) == 2


def test_epss_offline(make_http: MakeHttp, tmp_path: Path) -> None:
    router = Router(epss_empiricalsecurity_com=epss_host({"epss_scores-2026-10-10.csv.gz": CSV}))
    cache = tmp_path / "c"
    with pytest.raises(NetworkError):
        fetch_epss_csv(make_http(router, offline=True, cache=cache), today=TODAY)
    assert router.requests == []
    fetch_epss_csv(make_http(router, cache=cache), today=TODAY)
    scores = load_epss(make_http(router, offline=True, cache=cache), {"CVE-2024-6119"}, today=TODAY)
    assert scores == {"CVE-2024-6119": (0.01234, 0.55)}
    assert len(router.requests) == 1


def test_epss_api_chunking() -> None:
    cves = [f"CVE-2024-{n:05d}" for n in range(250)]
    chunks = _chunks(cves)
    assert sum(len(c) for c in chunks) == 250
    for c in chunks:
        assert len(c) <= API_MAX_CVES
        assert len(",".join(c)) <= API_MAX_CHARS


def test_epss_falls_back_to_api(make_http: MakeHttp) -> None:
    seen: list[list[str]] = []

    def api(request: httpx.Request) -> httpx.Response:
        cves = parse_qs(request.url.query.decode())["cve"][0].split(",")
        seen.append(cves)
        data = [{"cve": c, "epss": "0.5", "percentile": "0.9", "date": "2026-10-09"} for c in cves]
        return httpx.Response(200, json={"status": "OK", "data": data})

    router = Router(epss_empiricalsecurity_com=epss_host({}), api_first_org=api)
    cves = {f"CVE-2024-{n:05d}" for n in range(150)}
    scores = load_epss(make_http(router), cves, today=TODAY)
    assert len(scores) == 150
    assert all(len(",".join(c)) <= API_MAX_CHARS for c in seen)
    assert len(seen) == 2
    assert epss_from_api(make_http(router), []) == {}


# --------------------------------------------------------------------------- KEV
def test_parse_kev() -> None:
    cat = parse_kev((DATA / "kev.json").read_bytes())
    assert cat.version == "2026.10.08"
    log4j = cat.entries["CVE-2021-44228"]
    assert log4j.ransomware is True
    assert log4j.vendor_project == "Apache"
    assert log4j.date_added
    assert log4j.due_date
    assert log4j.required_action
    assert cat.entries["CVE-2015-5477"].ransomware is False
    with pytest.raises(NetworkError):
        parse_kev(b"{}")


def kev_host(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=(DATA / "kev.json").read_bytes())


def test_kev_cached(make_http: MakeHttp) -> None:
    router = Router(www_cisa_gov=kev_host)
    http = make_http(router)
    load_kev(http)
    load_kev(http)
    assert len(router.requests) == 1


# --------------------------------------------------------------------------- enrichment
def test_enrichment_end_to_end(
    fake_osv: FakeOsv, records: dict[str, Any], make_http: MakeHttp, vctx: MakeCtx
) -> None:
    records["GHSA-jfh8-c2jp-5v3q"] = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2021-44228"],
        "affected": [
            {
                "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}
                ],
            }
        ],
    }
    fake_osv.add("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "GHSA-jfh8-c2jp-5v3q")
    router = Router(
        api_osv_dev=fake_osv,
        www_cisa_gov=kev_host,
        epss_empiricalsecurity_com=epss_host({"*": gzip.compress(CSV)}),
    )
    p = pkg(
        "log4j-core",
        "2.14.1",
        PackageType.MAVEN,
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    )
    ctx = vctx(epss=True, kev=True)
    vulns = match_vulnerabilities(ctx, [p], make_http(router))
    assert len(vulns) == 1
    v = vulns[0]
    assert v.kev is not None
    assert v.kev.ransomware
    assert (v.epss, v.epss_percentile) == (0.944, 0.9999)
    assert v.fixed_versions == ["2.15.0"]


def test_enrichment_failure_is_limitation(
    fake_osv: FakeOsv, make_http: MakeHttp, vctx: MakeCtx
) -> None:
    fake_osv.add("Debian:12", "openssl", "3.0.11-1~deb12u2", "DSA-5764-1")
    router = Router(api_osv_dev=fake_osv)  # cisa / epss hosts answer 503
    ctx = vctx("Debian:12", epss=True, kev=True)
    vulns = match_vulnerabilities(ctx, [pkg("openssl", "3.0.11-1~deb12u2")], make_http(router))
    assert [v.id for v in vulns] == ["CVE-2024-6119"]
    assert vulns[0].kev is None
    assert vulns[0].epss is None
    assert any(m.startswith("kev:") for m in ctx.limitations)
    assert any(m.startswith("epss:") for m in ctx.limitations)


# --------------------------------------------------------------------------- db update
def test_update_feeds_and_status(make_http: MakeHttp, tmp_path: Path) -> None:
    import datetime as dt

    today = dt.datetime.now(dt.UTC).date().isoformat()
    router = Router(
        www_cisa_gov=kev_host,
        epss_empiricalsecurity_com=epss_host({f"epss_scores-{today}.csv.gz": gzip.compress(CSV)}),
        security_archlinux_org=lambda r: httpx.Response(
            200, content=(DATA / "arch_all.json").read_bytes()
        ),
    )
    cache = tmp_path / "feeds"
    before = feed_status(make_http(router, cache=cache))
    assert before == {"kev": "missing", "epss": "missing", "arch": "missing"}
    assert router.requests == []
    status = update_feeds(make_http(router, cache=cache), arch=True)
    assert status["kev"].startswith("ok: catalog 2026.10.08")
    assert status["epss"] == "ok: scores 2026-10-09, 3 CVEs"
    assert status["arch"].startswith("ok: 6 advisory groups")
    n = len(router.requests)
    after = feed_status(make_http(router, cache=cache))
    assert len(router.requests) == n  # status never touches the network
    assert after["kev"].startswith("cached: catalog 2026.10.08")
    assert after["epss"].startswith(f"cached: scores {today}")
    assert after["arch"] == "cached: 6 advisory groups"


def test_update_feeds_errors_are_reported(make_http: MakeHttp) -> None:
    status = update_feeds(make_http(Router()))
    assert status["kev"].startswith("error:")
    assert status["epss"].startswith("error:")
