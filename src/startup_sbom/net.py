"""Hardened HTTP access for remote data sources.

* HTTPS only, to an explicit host allow-list; TLS verification is never disabled.
* Explicit timeouts, bounded retries with exponential backoff on 429/5xx.
* Optional on-disk cache with TTL and ETag / Last-Modified revalidation.
* A hard offline mode: no socket is ever opened, only fresh-or-stale cache is served.
* Secrets (API keys) travel in headers only and are never logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import platformdirs

from startup_sbom import __version__
from startup_sbom.errors import NetworkError

log = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset(
    {
        "api.osv.dev",
        "osv-vulnerabilities.storage.googleapis.com",
        "api.first.org",
        "epss.empiricalsecurity.com",
        "www.cisa.gov",
        "security.archlinux.org",
        "services.nvd.nist.gov",
        "endoflife.date",
    }
)

MAX_RESPONSE_BYTES = 256 * 1024 * 1024


def default_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir("startup-sbom", appauthor=False))


@dataclass(slots=True)
class Response:
    status: int
    content: bytes
    from_cache: bool = False
    stale: bool = False

    def json(self) -> Any:
        return json.loads(self.content)


class HttpClient:
    """Small synchronous HTTP client shared by all remote sources of a scan."""

    def __init__(
        self,
        *,
        offline: bool = False,
        cache_dir: Path | None = None,
        timeout: float = 30.0,
        retries: int = 3,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.offline = offline
        self.cache_dir = cache_dir if cache_dir is not None else default_cache_dir()
        self.retries = retries
        self._client: httpx.Client | None = None
        self._timeout = httpx.Timeout(timeout, connect=min(timeout, 10.0))
        self._transport = transport
        self._lock = threading.Lock()

    # -- plumbing -------------------------------------------------------------
    @property
    def client(self) -> httpx.Client:
        with self._lock:
            if self._client is None:
                self._client = httpx.Client(
                    timeout=self._timeout,
                    follow_redirects=False,
                    verify=True,
                    headers={"User-Agent": f"startup-sbom/{__version__}"},
                    transport=self._transport,
                )
            return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def _check_url(url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
            raise NetworkError(f"refusing request to non-allow-listed URL: {parts.hostname}")

    def _cache_paths(self, key: str) -> tuple[Path, Path]:
        digest = hashlib.sha256(key.encode()).hexdigest()
        base = self.cache_dir / "http" / digest[:2]
        return base / digest, base / (digest + ".meta.json")

    def _read_cache(self, key: str) -> tuple[bytes, dict[str, Any]] | None:
        body_path, meta_path = self._cache_paths(key)
        try:
            meta = json.loads(meta_path.read_text("utf-8"))
            return body_path.read_bytes(), meta
        except (OSError, ValueError):
            return None

    def _write_cache(self, key: str, body: bytes, headers: Mapping[str, str]) -> None:
        body_path, meta_path = self._cache_paths(key)
        meta = {
            "fetched": time.time(),
            "etag": headers.get("etag"),
            "last_modified": headers.get("last-modified"),
        }
        try:
            body_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(body_path, body)
            _atomic_write(meta_path, json.dumps(meta).encode())
        except OSError as exc:
            log.debug("cache write failed: %s", exc)

    def _touch_cache(self, key: str, meta: dict[str, Any]) -> None:
        _, meta_path = self._cache_paths(key)
        meta["fetched"] = time.time()
        try:
            _atomic_write(meta_path, json.dumps(meta).encode())
        except OSError as exc:
            log.debug("cache touch failed: %s", exc)

    # -- requests -------------------------------------------------------------
    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        params: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        self._check_url(url)
        if self.offline:
            raise NetworkError("offline mode: network access disabled")
        delay = 1.0
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                resp = self.client.request(
                    method, url, headers=headers, json=json_body, params=params
                )
            except httpx.HTTPError as exc:
                last_exc = exc
            else:
                if resp.status_code not in (429, 500, 502, 503, 504):
                    if len(resp.content) > MAX_RESPONSE_BYTES:
                        raise NetworkError(f"response from {urlsplit(url).hostname} too large")
                    return resp
                last_exc = NetworkError(f"HTTP {resp.status_code}")
                retry_after = resp.headers.get("retry-after", "")
                if retry_after.isdigit():
                    delay = min(float(retry_after), 60.0)
            if attempt < self.retries:
                time.sleep(delay)
                delay = min(delay * 2, 30.0)
        host = urlsplit(url).hostname
        raise NetworkError(f"request to {host} failed: {last_exc}")

    def get(
        self,
        url: str,
        *,
        ttl: float | None = None,
        params: Mapping[str, str] | None = None,
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
    ) -> Response:
        """GET with optional caching.  ``ttl`` (seconds) enables the cache."""
        key = cache_key or url + ("?" + json.dumps(dict(params), sort_keys=True) if params else "")
        cached = self._read_cache(key) if ttl is not None else None
        if cached is not None:
            body, meta = cached
            age = time.time() - float(meta.get("fetched", 0))
            if age <= (ttl or 0) or self.offline:
                return Response(200, body, from_cache=True, stale=age > (ttl or 0))
        if self.offline:
            raise NetworkError(f"offline mode and no cached copy of {urlsplit(url).hostname}")
        req_headers = dict(headers or {})
        if cached is not None:
            _, meta = cached
            if meta.get("etag"):
                req_headers["If-None-Match"] = str(meta["etag"])
            if meta.get("last_modified"):
                req_headers["If-Modified-Since"] = str(meta["last_modified"])
        try:
            resp = self._send("GET", url, headers=req_headers, params=params)
        except NetworkError:
            if cached is not None:
                log.warning("using stale cache for %s", urlsplit(url).hostname)
                return Response(200, cached[0], from_cache=True, stale=True)
            raise
        if resp.status_code == 304 and cached is not None:
            self._touch_cache(key, cached[1])
            return Response(200, cached[0], from_cache=True)
        if not 200 <= resp.status_code < 300:
            raise NetworkError(f"HTTP {resp.status_code} from {urlsplit(url).hostname}")
        if ttl is not None:
            self._write_cache(key, resp.content, resp.headers)
        return Response(resp.status_code, resp.content)

    def post_json(self, url: str, body: Any, *, headers: dict[str, str] | None = None) -> Response:
        """POST a JSON body (never cached)."""
        resp = self._send("POST", url, json_body=body, headers=headers)
        if not 200 <= resp.status_code < 300:
            raise NetworkError(f"HTTP {resp.status_code} from {urlsplit(url).hostname}")
        return Response(resp.status_code, resp.content)

    # -- generic json cache for derived data ----------------------------------
    def cache_get_json(self, namespace: str, key: str, ttl: float) -> Any | None:
        cached = self._read_cache(f"{namespace}:{key}")
        if cached is None:
            return None
        body, meta = cached
        age = time.time() - float(meta.get("fetched", 0))
        if age > ttl and not self.offline:
            return None
        try:
            return json.loads(body)
        except ValueError:
            return None

    def cache_put_json(self, namespace: str, key: str, value: Any) -> None:
        self._write_cache(f"{namespace}:{key}", json.dumps(value).encode(), {})


def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
