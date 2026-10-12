"""Optional, pluggable web search with the user's own key or instance (disabled by default).

There is no free, key-less, ToS-compliant web-search API, and search engines are
never scraped.  Providers only contribute *candidate URLs*; every hit still goes
through :class:`~startup_sbom.intel.fetcher.SafeFetcher` like any other reference.
Keys travel in headers only and are never logged or written to a report.
Configure with ``STARTUP_SBOM_SEARCH=brave|tavily|searxng`` plus ``BRAVE_API_KEY``,
``TAVILY_API_KEY`` or ``SEARXNG_URL``; nothing is wired into prefetch unless a
provider is passed explicitly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from startup_sbom import __version__
from startup_sbom.errors import NetworkError
from startup_sbom.intel.select import Reference
from startup_sbom.textsafe import safe

BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
TAVILY_URL = "https://api.tavily.com/search"
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_HITS = 20


@dataclass(slots=True, frozen=True)
class SearchHit:
    url: str
    title: str | None = None
    snippet: str | None = None


class SearchProvider(Protocol):
    name: str

    def search(self, query: str, *, limit: int) -> list[SearchHit]: ...


def _client(timeout: float, transport: httpx.BaseTransport | None) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
        follow_redirects=False,
        verify=True,
        trust_env=False,
        headers={"User-Agent": f"startup-sbom/{__version__}"},
        transport=transport,
    )


def _hits(
    items: object, url_key: str, title_key: str, text_key: str, limit: int
) -> list[SearchHit]:
    out: list[SearchHit] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        url = item.get(url_key)
        if not isinstance(url, str) or not url.lower().startswith(("https://", "http://")):
            continue
        out.append(
            SearchHit(
                url=url.strip()[:2048],
                title=safe(item.get(title_key) or "", 200) or None,
                snippet=safe(item.get(text_key) or "", 300) or None,
            )
        )
        if len(out) >= min(limit, MAX_HITS):
            break
    return out


def _json(resp: httpx.Response, name: str) -> Any:
    if resp.status_code != 200:
        raise NetworkError(f"search provider {name}: HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise NetworkError(f"search provider {name}: malformed response") from exc


class BraveProvider:
    """Brave Search API (``X-Subscription-Token``)."""

    name = "brave"

    def __init__(
        self, api_key: str, *, timeout: float = 15.0, transport: httpx.BaseTransport | None = None
    ) -> None:
        if not api_key:
            raise ValueError("Brave search needs an API key")
        self._key = api_key
        self._client = _client(timeout, transport)

    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        try:
            resp = self._client.get(
                BRAVE_URL,
                params={"q": query, "count": str(min(limit, MAX_HITS))},
                headers={"X-Subscription-Token": self._key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise NetworkError(f"search provider brave: {type(exc).__name__}") from exc
        doc = _json(resp, self.name)
        web = doc.get("web") if isinstance(doc, dict) else None
        results = web.get("results") if isinstance(web, dict) else None
        return _hits(results, "url", "title", "description", limit)


class TavilyProvider:
    """Tavily search API (bearer token)."""

    name = "tavily"

    def __init__(
        self, api_key: str, *, timeout: float = 20.0, transport: httpx.BaseTransport | None = None
    ) -> None:
        if not api_key:
            raise ValueError("Tavily search needs an API key")
        self._key = api_key
        self._client = _client(timeout, transport)

    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        try:
            resp = self._client.post(
                TAVILY_URL,
                json={"query": query, "max_results": min(limit, MAX_HITS)},
                headers={"Authorization": f"Bearer {self._key}"},
            )
        except httpx.HTTPError as exc:
            raise NetworkError(f"search provider tavily: {type(exc).__name__}") from exc
        doc = _json(resp, self.name)
        results = doc.get("results") if isinstance(doc, dict) else None
        return _hits(results, "url", "title", "content", limit)


class SearxngProvider:
    """A user's own SearXNG instance (``search.formats`` must include ``json``)."""

    name = "searxng"

    def __init__(
        self, base_url: str, *, timeout: float = 15.0, transport: httpx.BaseTransport | None = None
    ) -> None:
        parts = urlsplit(base_url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOOPBACK):
            raise ValueError("SearXNG URL must be https (http only for a loopback instance)")
        if parts.username or parts.password:
            raise ValueError("SearXNG URL must not contain credentials")
        self._url = base_url.rstrip("/") + "/search"
        self._client = _client(timeout, transport)

    def search(self, query: str, *, limit: int) -> list[SearchHit]:
        try:
            resp = self._client.get(self._url, params={"q": query, "format": "json"})
        except httpx.HTTPError as exc:
            raise NetworkError(f"search provider searxng: {type(exc).__name__}") from exc
        doc = _json(resp, self.name)
        results = doc.get("results") if isinstance(doc, dict) else None
        return _hits(results, "url", "title", "content", limit)


def provider_from_env(env: Mapping[str, str] | None = None) -> SearchProvider | None:
    """The configured provider, or None (the default: search disabled)."""
    source = os.environ if env is None else env
    choice = source.get("STARTUP_SBOM_SEARCH", "").strip().lower()
    if choice == "brave" and source.get("BRAVE_API_KEY"):
        return BraveProvider(source["BRAVE_API_KEY"])
    if choice == "tavily" and source.get("TAVILY_API_KEY"):
        return TavilyProvider(source["TAVILY_API_KEY"])
    if choice == "searxng" and source.get("SEARXNG_URL"):
        return SearxngProvider(source["SEARXNG_URL"])
    return None


def search_references(provider: SearchProvider, cve: str, *, limit: int = 5) -> list[Reference]:
    """One query per CVE; hits become candidate references (``origin=search:<name>``)."""
    hits = provider.search(f'"{cve}" exploit OR writeup OR advisory', limit=limit)
    return [Reference(h.url, f"search:{provider.name}") for h in hits]
