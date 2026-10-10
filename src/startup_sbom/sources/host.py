"""The running Linux host (``host:``) and its live runtime facts.

``host:`` analyses ``/`` read-only through :class:`DirectoryRootFS`.  The live
helpers only ever read the *host's* own ``/proc`` or run the *host's*
``systemd-analyze``; they are never used for any other target, and nothing
from an analysed image is ever executed.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import struct
import subprocess
import sys

from startup_sbom.boottime import parse_blame
from startup_sbom.errors import TargetError
from startup_sbom.models import ListenAddress
from startup_sbom.rootfs import DirectoryRootFS

log = logging.getLogger(__name__)

TCP_LISTEN = "0A"
UDP_UNCONNECTED = "07"
BLAME_TIMEOUT = 30.0
_MAX_PROC_NET = 64 * 1024 * 1024


def is_linux() -> bool:
    """True on a Linux host."""
    return sys.platform.startswith("linux")


def open_host(root: str = "/") -> DirectoryRootFS:
    """Open the live host root read-only (Linux only)."""
    if not is_linux():
        raise TargetError(
            "host: scans the running Linux host and is only supported on Linux; on "
            f"{sys.platform} scan an image (docker:<image>, docker-archive:<file>) or a "
            "directory (dir:<path>) instead"
        )
    return DirectoryRootFS(root)


def is_systemd_booted(root: str = "/") -> bool:
    """True if the host was booted with systemd (``/run/systemd/system`` exists)."""
    return is_linux() and os.path.isdir(os.path.join(root, "run", "systemd", "system"))


def _decode_addr(hexaddr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    # Each 32-bit word is printed with %08X in host byte order: re-pack natively.
    words = [int(hexaddr[i : i + 8], 16) for i in range(0, len(hexaddr), 8)]
    raw = b"".join(struct.pack("=I", w) for w in words)
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw)
    addr = ipaddress.IPv6Address(raw)
    return addr.ipv4_mapped or addr


def parse_proc_net(text: str, protocol: str, source: str) -> list[ListenAddress]:
    """Parse one ``/proc/net/{tcp,tcp6,udp,udp6}`` table into listening sockets."""
    want = TCP_LISTEN if protocol == "tcp" else UDP_UNCONNECTED
    out: list[ListenAddress] = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or cols[3].upper() != want:
            continue
        addr_hex, _, port_hex = cols[1].partition(":")
        try:
            addr = _decode_addr(addr_hex)
            port = int(port_hex, 16)
        except (ValueError, struct.error):
            continue
        out.append(
            ListenAddress(
                protocol=protocol,
                address=str(addr),
                port=port,
                scope="loopback" if addr.is_loopback else "network",
                source=source,
            )
        )
    return out


def live_listeners(proc_root: str = "/proc") -> list[ListenAddress]:
    """Listening TCP and bound UDP sockets of the host network namespace (Linux only)."""
    if not is_linux():
        return []
    found: dict[tuple[str, str | None, int | None], ListenAddress] = {}
    for fname, protocol in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        path = os.path.join(proc_root, "net", fname)
        try:
            with open(path, "rb") as f:
                text = f.read(_MAX_PROC_NET).decode("ascii", "replace")
        except OSError:
            continue
        for la in parse_proc_net(text, protocol, f"/proc/net/{fname}"):
            found.setdefault((la.protocol, la.address, la.port), la)
    return sorted(found.values(), key=lambda la: (la.protocol, la.port or 0, la.address or ""))


def live_boot_timing() -> dict[str, float]:
    """Unit start-up times from the running host's ``systemd-analyze blame`` (ms)."""
    if not is_systemd_booted():
        return {}
    exe = shutil.which("systemd-analyze")
    if not exe:
        log.info("systemd-analyze not found; boot timing unavailable")
        return {}
    try:
        proc = subprocess.run(  # noqa: S603 - host tool, fixed argv, no shell
            [exe, "blame", "--no-pager"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=BLAME_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("systemd-analyze blame failed: %s", exc)
        return {}
    if proc.returncode != 0:
        log.warning("systemd-analyze blame exited with %d", proc.returncode)
        return {}
    return parse_blame(proc.stdout[: 8 * 1024 * 1024].decode("utf-8", "replace"))
