"""endoflife.date lookup with a mocked transport."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import httpx
import pytest

from startup_sbom.models import OSInfo
from startup_sbom.net import HttpClient
from startup_sbom.supplychain.eol import eol_key, lookup_eol

TODAY = date(2026, 10, 10)
RELEASES = {
    "/api/v1/products/debian/releases/11": {
        "name": "11",
        "codename": "Bullseye",
        "isLts": True,
        "isEol": True,
        "eolFrom": "2026-08-31",
    },
    "/api/v1/products/ubuntu/releases/24.04": {
        "name": "24.04",
        "isLts": True,
        "isEol": False,
        "eolFrom": "2029-05-31",
    },
    "/api/v1/products/fedora/releases/44": {"name": "44", "isEol": False, "eolFrom": None},
}


class _Server:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        body = RELEASES.get(request.url.path)
        if body is None:
            return httpx.Response(404, json={"message": "Not found"})
        return httpx.Response(200, content=json.dumps({"schema_version": "1.2.1", "result": body}))


def _client(tmp_path: Path, server: _Server | None = None, *, offline: bool = False) -> HttpClient:
    transport = httpx.MockTransport(server) if server is not None else None
    return HttpClient(offline=offline, cache_dir=tmp_path, retries=0, transport=transport)


def test_eol_and_not_eol(tmp_path: Path) -> None:
    server = _Server()
    http = _client(tmp_path, server)
    deb = lookup_eol(OSInfo(id="debian", version_id="11"), http, today=TODAY)
    assert deb is not None
    assert (deb.product, deb.cycle, deb.eol_date, deb.is_eol, deb.lts) == (
        "debian",
        "11",
        "2026-08-31",
        True,
        True,
    )
    ubu = lookup_eol(OSInfo(id="ubuntu", version_id="24.04"), http, today=TODAY)
    assert ubu is not None
    assert ubu.is_eol is False
    assert ubu.eol_date == "2029-05-31"
    fed = lookup_eol(OSInfo(id="fedora", version_id="44"), http)
    assert fed is not None
    assert fed.is_eol is False
    assert fed.eol_date is None
    # cached for a week: no second request
    lookup_eol(OSInfo(id="debian", version_id="11"), http, today=TODAY)
    assert server.calls.count("/api/v1/products/debian/releases/11") == 1


def test_is_eol_uses_current_date_by_default(tmp_path: Path) -> None:
    RELEASES["/api/v1/products/rhel/releases/6"] = {
        "name": "6",
        "isEol": False,
        "eolFrom": "2020-11-30",
    }
    try:
        info = lookup_eol(OSInfo(id="rhel", version_id="6.10"), _client(tmp_path, _Server()))
    finally:
        del RELEASES["/api/v1/products/rhel/releases/6"]
    assert info is not None
    assert info.is_eol is True


def test_unknown_product_or_cycle(tmp_path: Path) -> None:
    server = _Server()
    http = _client(tmp_path, server)
    assert lookup_eol(OSInfo(id="photon", version_id="5.0"), http) is None
    assert server.calls == ["/api/v1/products/photon/releases/5.0"]
    assert lookup_eol(OSInfo(id="myos", version_id="1"), http) is None
    assert lookup_eol(OSInfo(id="debian"), http) is None  # sid: no VERSION_ID
    assert server.calls == ["/api/v1/products/photon/releases/5.0"]


def test_offline_is_cache_only(tmp_path: Path) -> None:
    assert lookup_eol(OSInfo(id="debian", version_id="11"), _client(tmp_path, offline=True)) is None
    lookup_eol(OSInfo(id="debian", version_id="11"), _client(tmp_path, _Server()), today=TODAY)
    cached = lookup_eol(
        OSInfo(id="debian", version_id="11"), _client(tmp_path, offline=True), today=TODAY
    )
    assert cached is not None
    assert cached.is_eol is True


@pytest.mark.parametrize(
    ("os_info", "expected"),
    [
        (OSInfo(id="alpine", version_id="3.20.3"), ("alpine-linux", "3.20")),
        (OSInfo(id="rhel", version_id="9.4"), ("rhel", "9")),
        (OSInfo(id="rocky", version_id="9.4"), ("rocky-linux", "9")),
        (OSInfo(id="almalinux", version_id="8.10"), ("almalinux", "8")),
        (OSInfo(id="amzn", version_id="2023"), ("amazon-linux", "2023")),
        (OSInfo(id="opensuse-leap", version_id="15.6"), ("opensuse", "15.6")),
        (OSInfo(id="sles", version_id="15.6"), ("sles", "15.6")),
        (OSInfo(id="ol", version_id="9.3"), ("oracle-linux", "9")),
        (OSInfo(id="centos", version_id="9", name="CentOS Stream"), ("centos-stream", "9")),
        (OSInfo(id="centos", version_id="7"), ("centos", "7")),
        (OSInfo(id="arch"), ("arch", "rolling")),
        (OSInfo(id="endeavouros", id_like=["arch"]), ("arch", "rolling")),
        (OSInfo(id="debian", version_id="../../etc"), None),
        (OSInfo(id="ubuntu", version_id="24.04?x=1"), None),
    ],
)
def test_eol_key_mapping(os_info: OSInfo, expected: tuple[str, str] | None) -> None:
    assert eol_key(os_info) == expected


def test_rolling_needs_no_network(tmp_path: Path) -> None:
    info = lookup_eol(OSInfo(id="arch"), _client(tmp_path, offline=True))
    assert info is not None
    assert info.cycle == "rolling"
    assert info.is_eol is False
