"""Shared helpers for vulnerability tests (fake OSV.dev, host router, package factory)."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from startup_sbom.models import Package, PackageType

DATA = Path(__file__).parent / "data"

Handler = Callable[[httpx.Request], httpx.Response]


def load_records() -> dict[str, dict[str, Any]]:
    out = {}
    for path in sorted((DATA / "osv").glob("*.json")):
        rec = json.loads(path.read_text("utf-8"))
        out[rec["id"]] = rec
    return out


class FakeOsv:
    """Minimal OSV.dev: querybatch over an index, vulns/{id} over records."""

    def __init__(self, records: dict[str, dict[str, Any]]) -> None:
        self.records = records
        self.index: dict[tuple[str, str, str], list[str]] = {}
        self.page_size: int | None = None
        self.batches: list[list[dict[str, Any]]] = []
        self.gets: list[str] = []
        self.fail_batch = False
        self._lock = threading.Lock()

    def add(self, ecosystem: str, name: str, version: str, *ids: str) -> None:
        self.index.setdefault((ecosystem, name, version), []).extend(ids)

    def modified(self, vid: str) -> str:
        return str(self.records.get(vid, {}).get("modified", "2026-01-01T00:00:00Z"))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/v1/querybatch":
            if self.fail_batch:
                return httpx.Response(400, json={"code": 3})
            queries = json.loads(request.content)["queries"]
            if len(queries) > 1000:
                return httpx.Response(400, json={"code": 3, "message": "too many queries"})
            with self._lock:
                self.batches.append(queries)
            results = []
            for q in queries:
                key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                ids = self.index.get(key, [])
                start = int(q.get("page_token") or 0)
                end = len(ids) if self.page_size is None else start + self.page_size
                page = ids[start:end]
                res: dict[str, Any] = {}
                if page:
                    res["vulns"] = [{"id": i, "modified": self.modified(i)} for i in page]
                if end < len(ids):
                    res["next_page_token"] = str(end)
                results.append(res)
            return httpx.Response(200, json={"results": results})
        if request.method == "GET" and path.startswith("/v1/vulns/"):
            vid = path.removeprefix("/v1/vulns/")
            with self._lock:
                self.gets.append(vid)
            if vid not in self.records:
                return httpx.Response(404, json={"code": 5})
            return httpx.Response(200, json=self.records[vid])
        return httpx.Response(404)


class Router:
    """Dispatch by host to handlers; records every request URL."""

    def __init__(self, **hosts: Handler) -> None:
        self.hosts = {k.replace("_", "."): v for k, v in hosts.items()}
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.hosts.get(request.url.host)
        if handler is None:
            return httpx.Response(503)
        return handler(request)


def pkg(
    name: str,
    version: str,
    ptype: PackageType = PackageType.DEB,
    *,
    source: str | None = None,
    source_version: str | None = None,
    epoch: int | None = None,
    purl: str | None = None,
    cpes: list[str] | None = None,
) -> Package:
    return Package(
        id=f"pkg:{ptype}/{name}@{version}",
        type=ptype,
        name=name,
        version=version,
        epoch=epoch,
        source_name=source,
        source_version=source_version,
        purl=purl,
        cpes=cpes or [],
    )


def mkrec(
    vid: str,
    ecosystem: str,
    name: str,
    events: list[dict[str, str]],
    **extra: Any,
) -> dict[str, Any]:
    """A synthetic OSV record with one affected entry."""
    entry: dict[str, Any] = {
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{"type": "ECOSYSTEM", "events": events}],
    }
    if "ecosystem_specific" in extra:
        entry["ecosystem_specific"] = extra.pop("ecosystem_specific")
    rec: dict[str, Any] = {"id": vid, "modified": "2026-10-01T00:00:00Z", "affected": [entry]}
    rec.update(extra)
    return rec
