"""Fixtures for intel tests.  Nothing here opens a socket."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

from intel.helpers import FakeFeeds, FakeWeb, make_fetcher
from startup_sbom.intel.fetcher import SafeFetcher
from startup_sbom.intel.store import IntelStore
from startup_sbom.net import HttpClient


@pytest.fixture
def feeds() -> FakeFeeds:
    return FakeFeeds()


@pytest.fixture
def web() -> FakeWeb:
    return FakeWeb()


@pytest.fixture
def make_http(tmp_path: Path, feeds: FakeFeeds) -> Callable[..., HttpClient]:
    def _make(*, offline: bool = False, cache: Path | None = None) -> HttpClient:
        return HttpClient(
            offline=offline,
            cache_dir=cache or tmp_path / "cache",
            retries=0,
            transport=httpx.MockTransport(feeds),
        )

    return _make


@pytest.fixture
def store(tmp_path: Path) -> IntelStore:
    return IntelStore(tmp_path / "cache" / "intel")


@pytest.fixture
def fetcher(web: FakeWeb) -> Iterator[SafeFetcher]:
    fetch = make_fetcher(web)
    yield fetch
    fetch.close()
