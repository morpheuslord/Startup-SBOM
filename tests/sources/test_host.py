"""host: mode and live-host helpers (no real systemd-analyze is run)."""

from __future__ import annotations

import ipaddress
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from startup_sbom.errors import TargetError
from startup_sbom.sources import host, open_target
from startup_sbom.sources.host import live_boot_timing, live_listeners, parse_proc_net

ANY4 = "0.0.0.0"  # noqa: S104 - /proc fixture data
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"


def _hex(ip: str) -> str:
    """Encode an address the way the kernel prints it (native-endian 32-bit words)."""
    raw = ipaddress.ip_address(ip).packed
    return "".join(f"{struct.unpack('=I', raw[i : i + 4])[0]:08X}" for i in range(0, len(raw), 4))


def _row(n: int, ip: str, port: int, state: str) -> str:
    return (
        f"   {n}: {_hex(ip)}:{port:04X} {_hex(ip)}:0000 {state} 00000000:00000000 "
        "00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0\n"
    )


@pytest.fixture
def proc_root(tmp_path: Path) -> Path:
    net = tmp_path / "net"
    net.mkdir()
    (net / "tcp").write_text(
        HEADER
        + _row(0, "127.0.0.1", 631, "0A")
        + _row(1, ANY4, 22, "0A")
        + _row(2, "10.0.0.5", 51000, "01")  # established: ignored
        + "garbage line\n"
    )
    (net / "tcp6").write_text(HEADER + _row(0, "::", 22, "0A") + _row(1, "::1", 5432, "0A"))
    (net / "udp").write_text(HEADER + _row(0, ANY4, 68, "07") + _row(1, "127.0.0.53", 53, "07"))
    (net / "udp6").write_text(HEADER + _row(0, "::ffff:127.0.0.1", 323, "07"))
    return tmp_path


def test_parse_proc_net_scopes() -> None:
    rows = parse_proc_net(HEADER + _row(0, "127.0.0.1", 631, "0A"), "tcp", "/proc/net/tcp")
    assert len(rows) == 1
    assert (rows[0].address, rows[0].port, rows[0].scope) == ("127.0.0.1", 631, "loopback")


def test_live_listeners(proc_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host, "is_linux", lambda: True)
    got = [(la.protocol, la.address, la.port, la.scope) for la in live_listeners(str(proc_root))]
    assert got == [
        ("tcp", ANY4, 22, "network"),
        ("tcp", "::", 22, "network"),
        ("tcp", "127.0.0.1", 631, "loopback"),
        ("tcp", "::1", 5432, "loopback"),
        ("udp", "127.0.0.53", 53, "loopback"),
        ("udp", ANY4, 68, "network"),
        ("udp", "127.0.0.1", 323, "loopback"),
    ]


def test_live_listeners_non_linux(proc_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host, "is_linux", lambda: False)
    assert live_listeners(str(proc_root)) == []


def test_host_target_requires_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host, "is_linux", lambda: False)
    with pytest.raises(TargetError, match="only supported on Linux"):
        open_target("host:")


def test_host_target_on_linux(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(host, "is_linux", lambda: True)
    fs = host.open_host(str(tmp_path))
    assert fs.root == str(tmp_path.resolve()) or fs.root.endswith(tmp_path.name)
    if sys.platform.startswith("linux"):
        with open_target("host:") as acq:
            assert acq.live_host
            assert acq.target.kind == "host"
            assert acq.container is None


BLAME = b"""\
     1min 2.345s plymouth-quit-wait.service
          5.123s NetworkManager-wait-online.service
           812ms dev-sda1.device
"""


def test_live_boot_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, BLAME, b"")

    monkeypatch.setattr(host, "is_systemd_booted", lambda root="/": True)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/systemd-analyze")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert live_boot_timing() == {
        "plymouth-quit-wait.service": 62345.0,
        "NetworkManager-wait-online.service": 5123.0,
        "dev-sda1.device": 812.0,
    }
    argv, kw = calls[0]
    assert argv == ["/usr/bin/systemd-analyze", "blame", "--no-pager"]
    assert "shell" not in kw
    assert kw["timeout"] > 0
    assert kw["stdin"] == subprocess.DEVNULL

    monkeypatch.setattr(
        subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"", b"x")
    )
    assert live_boot_timing() == {}


def test_live_boot_timing_not_systemd(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*a: object, **k: object) -> None:
        raise AssertionError("must not run anything")

    monkeypatch.setattr(host, "is_systemd_booted", lambda root="/": False)
    monkeypatch.setattr(subprocess, "run", explode)
    assert live_boot_timing() == {}
    monkeypatch.setattr(host, "is_systemd_booted", lambda root="/": True)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert live_boot_timing() == {}
