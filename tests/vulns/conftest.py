"""Fixtures for vulnerability-source tests.  Nothing here opens a socket."""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.models import OSInfo
from startup_sbom.net import HttpClient
from startup_sbom.rootfs import DirectoryRootFS
from vulns.helpers import FakeOsv, Handler, load_records


@pytest.fixture
def records() -> dict[str, dict[str, Any]]:
    return copy.deepcopy(load_records())


@pytest.fixture
def fake_osv(records: dict[str, dict[str, Any]]) -> FakeOsv:
    return FakeOsv(records)


@pytest.fixture
def make_http(tmp_path: Path) -> Callable[..., HttpClient]:
    def _make(handler: Handler, *, offline: bool = False, cache: Path | None = None) -> HttpClient:
        return HttpClient(
            offline=offline,
            cache_dir=cache or tmp_path / "cache",
            retries=0,
            transport=httpx.MockTransport(handler),
        )

    return _make


@pytest.fixture
def vctx(tmp_path: Path) -> Callable[..., ScanContext]:
    root = tmp_path / "root"
    root.mkdir()

    def _make(*ecosystems: str, os_id: str = "debian", **options: Any) -> ScanContext:
        options.setdefault("epss", False)
        options.setdefault("kev", False)
        return ScanContext(
            fs=DirectoryRootFS(root),
            options=ScanOptions(**options),
            os=OSInfo(id=os_id, vuln_ecosystems=list(ecosystems)),
        )

    return _make
