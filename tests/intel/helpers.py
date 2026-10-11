"""Shared helpers for intel tests: fake feeds, a harnessed SafeFetcher, report factory.

Nothing in here ever opens a socket: the allow-listed :class:`HttpClient` gets an
``httpx.MockTransport`` and the :class:`SafeFetcher` additionally gets a fake DNS
resolver, so DNS, TLS pinning and robots behaviour are all exercised in-process.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from startup_sbom.intel.fetcher import SafeFetcher
from startup_sbom.models import (
    SSVC,
    Report,
    ScanMetadata,
    Severity,
    SSVCDecision,
    TargetInfo,
    Threat,
    Vulnerability,
)

DATA = Path(__file__).parent / "data"
EPOCH = datetime(2026, 10, 10, 0, 0, 0, tzinfo=UTC)

# One public IP per fake hostname; SafeFetcher tests extend this map.
PUBLIC_DNS: dict[str, list[str]] = {
    "example.org": ["93.184.216.34"],
    "writeups.example.org": ["93.184.216.35"],
    "second.example.org": ["93.184.216.36"],
}


def load(name: str) -> bytes:
    return (DATA / name).read_bytes()


def load_json(name: str) -> Any:
    return json.loads(load(name))


# --------------------------------------------------------------------------- feeds
class FakeFeeds:
    """Routes allow-listed HttpClient traffic to the trimmed fixtures.

    ``self.calls`` records ``(host, path)`` per request; ``self.fail`` maps a host to
    an HTTP status to simulate a broken source.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}
        self._lock = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        with self._lock:
            self.calls.append((host, path))
        status = self.fail.get(host)
        if status is not None:
            return httpx.Response(status)
        if host == "cveawg.mitre.org" and path.startswith("/api/cve/"):
            cve = path.rsplit("/", 1)[-1]
            if (DATA / f"cve_{cve}.json").exists():
                return httpx.Response(200, content=load(f"cve_{cve}.json"))
            return httpx.Response(404)
        if host == "services.nvd.nist.gov":
            cve = request.url.params.get("cveId", "")
            if (DATA / f"nvd_{cve}.json").exists():
                return httpx.Response(200, content=load(f"nvd_{cve}.json"))
            return httpx.Response(200, json={"vulnerabilities": []})
        if host == "ubuntu.com":
            cve = path.rsplit("/", 1)[-1].removesuffix(".json")
            if (DATA / f"ubuntu_{cve}.json").exists():
                return httpx.Response(200, content=load(f"ubuntu_{cve}.json"))
            return httpx.Response(404)
        if host == "access.redhat.com":
            cve = path.rsplit("/", 1)[-1].removesuffix(".json")
            if (DATA / f"redhat_{cve}.json").exists():
                return httpx.Response(200, content=load(f"redhat_{cve}.json"))
            return httpx.Response(404)
        if host == "raw.githubusercontent.com" and "PoC-in-GitHub" in path:
            cve = path.rsplit("/", 1)[-1].removesuffix(".json")
            if (DATA / f"poc_{cve}.json").exists():
                return httpx.Response(200, content=load(f"poc_{cve}.json"))
            return httpx.Response(404)
        if host == "raw.githubusercontent.com" and path.endswith("modules_metadata_base.json"):
            return httpx.Response(200, content=load("modules_metadata_base.json"))
        if host == "raw.githubusercontent.com" and path.endswith("cves.json"):
            return httpx.Response(200, content=load("cves.json"))
        if host == "gitlab.com" and path.endswith("files_exploits.csv"):
            return httpx.Response(200, content=load("files_exploits.csv"))
        if host == "api.first.org":
            return httpx.Response(200, content=load("epss_timeseries.json"))
        if host == "api.github.com" and path == "/advisories":
            return httpx.Response(200, json=[])
        return httpx.Response(404)


# --------------------------------------------------------------------------- fetcher
class FakeWeb:
    """The open web as seen by the SafeFetcher: pages, robots and redirects by URL."""

    def __init__(self) -> None:
        self.pages: dict[str, tuple[int, bytes, dict[str, str]]] = {}
        self.robots: dict[str, str | int] = {}  # host -> robots.txt body or HTTP status
        self.requests: list[httpx.Request] = []
        self._lock = threading.Lock()

    def add_page(
        self,
        url: str,
        body: bytes | str,
        *,
        content_type: str = "text/html; charset=utf-8",
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        content = body.encode() if isinstance(body, str) else body
        self.pages[url] = (status, content, {"content-type": content_type, **(headers or {})})

    def add_redirect(self, url: str, location: str, *, status: int = 302) -> None:
        self.pages[url] = (status, b"", {"location": location})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append(request)
        host = request.headers.get("host", request.url.host)
        path_q = request.url.path + (f"?{request.url.query.decode()}" if request.url.query else "")
        if request.url.path == "/robots.txt":
            rule = self.robots.get(host, 404)
            if isinstance(rule, int):
                return httpx.Response(rule)
            return httpx.Response(200, text=rule, headers={"content-type": "text/plain"})
        page = self.pages.get(f"https://{host}{path_q}")
        if page is None:
            return httpx.Response(404, headers={"content-type": "text/html"})
        status, content, hdrs = page
        return httpx.Response(status, content=content, headers=hdrs)


def make_fetcher(
    web: FakeWeb,
    *,
    dns: dict[str, list[str]] | None = None,
    **kwargs: Any,
) -> SafeFetcher:
    """A SafeFetcher wired to the fake web: fake DNS, mock transport, no real sleeps."""
    table = {**PUBLIC_DNS, **(dns or {})}

    def resolver(host: str) -> list[str]:
        try:
            return table[host]
        except KeyError:
            raise OSError(f"NXDOMAIN {host}") from None

    kwargs.setdefault("host_delay", 0.0)
    kwargs.setdefault("sleep", lambda _s: None)
    return SafeFetcher(resolver=resolver, transport=httpx.MockTransport(web), **kwargs)


# --------------------------------------------------------------------------- reports
def make_vuln(cve: str, package: str = "pkg:deb/x", **kw: Any) -> Vulnerability:
    kw.setdefault("severity", Severity.HIGH)
    return Vulnerability(
        id=cve,
        package=package,
        package_name=package.rsplit("/", 1)[-1],
        installed_version="1.0",
        **kw,
    )


def make_threat(
    vuln_id: str,
    *,
    decision: SSVCDecision = SSVCDecision.TRACK,
    risk_score: float = 10.0,
    tid: str | None = None,
) -> Threat:
    return Threat(
        id=tid or f"threat:{vuln_id}",
        vulnerability=vuln_id,
        package="pkg:deb/x",
        title=f"{vuln_id} in x",
        reachability="installed",
        precondition="local",
        postcondition="root",
        narrative="test",
        risk_score=risk_score,
        ssvc=SSVC(
            exploitation="none",
            automatable="no",
            technical_impact="total",
            exposure="small",
            decision=decision,
        ),
    )


def make_report(
    vulnerabilities: list[Vulnerability] | None = None,
    threats: list[Threat] | None = None,
) -> Report:
    return Report(
        metadata=ScanMetadata(
            tool_version="2.0.0",
            scan_id="intel-test",
            started=EPOCH,
            target=TargetInfo(kind="dir", reference="/test"),
        ),
        vulnerabilities=vulnerabilities or [],
        threats=threats or [],
    )
