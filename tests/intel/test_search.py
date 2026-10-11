"""Optional search providers: disabled by default, keys in headers only."""

from __future__ import annotations

import httpx
import pytest

from startup_sbom.intel.search import (
    BraveProvider,
    SearxngProvider,
    TavilyProvider,
    provider_from_env,
    search_references,
)


def test_disabled_by_default() -> None:
    assert provider_from_env({}) is None
    assert provider_from_env({"BRAVE_API_KEY": "k"}) is None  # key alone does not enable
    assert provider_from_env({"STARTUP_SBOM_SEARCH": "brave"}) is None  # choice alone either
    assert provider_from_env({"STARTUP_SBOM_SEARCH": "duckduckgo"}) is None


def test_provider_from_env_selects() -> None:
    provider = provider_from_env({"STARTUP_SBOM_SEARCH": "brave", "BRAVE_API_KEY": "k"})
    assert provider is not None
    assert provider.name == "brave"


def test_searxng_rejects_unsafe_urls() -> None:
    with pytest.raises(ValueError, match="https"):
        SearxngProvider("http://searx.example.org")
    with pytest.raises(ValueError, match="credentials"):
        SearxngProvider("https://user:pw@searx.example.org")
    SearxngProvider("http://localhost:8888")  # a loopback instance may stay http


def test_brave_key_travels_in_header_and_hits_become_references() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {"url": "https://blog.example.org/x", "title": "T", "description": "D"},
                        {"url": "ftp://bad.example.org/x", "title": "skip"},
                    ]
                }
            },
        )

    provider = BraveProvider("sekrit", transport=httpx.MockTransport(handler))
    refs = search_references(provider, "CVE-2024-6387")
    (request,) = seen
    assert request.headers["x-subscription-token"] == "sekrit"
    assert "sekrit" not in str(request.url)  # never in the URL
    (ref,) = refs
    assert ref.url == "https://blog.example.org/x"
    assert ref.origin == "search:brave"


def test_tavily_uses_bearer_token() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"results": []})

    provider = TavilyProvider("tok", transport=httpx.MockTransport(handler))
    assert provider.search("q", limit=3) == []
    assert seen[0].headers["authorization"] == "Bearer tok"
