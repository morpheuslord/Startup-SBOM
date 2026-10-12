"""Socket-unit listeners: ``Listen*=`` grammar and reachability classification.

``ListenAddress.address`` is ``None`` for "all interfaces" (a bare port, which
systemd binds dual-stack on ``[::]``); ``0.0.0.0`` and ``::`` are kept literally
and are also scope ``network``.  Loopback addresses, ``BindToDevice=lo`` and
``IPAddressDeny=any`` + ``IPAddressAllow=localhost`` give scope ``loopback``;
unix sockets, FIFOs, netlink, special files and vsock are scope ``local``.
"""

from __future__ import annotations

import ipaddress
import re

from startup_sbom.models import ListenAddress

LISTEN_KEYS = (
    "ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenNetlink",
    "ListenFIFO", "ListenSpecial", "ListenMessageQueue", "ListenUSBFunction",
)  # fmt: skip
_V4_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$")
_V6_RE = re.compile(r"^\[([0-9A-Fa-f:.]+)\]:(\d+)(?:%[\w.-]+)?$")
_VSOCK_RE = re.compile(r"^vsock(?:-stream|-dgram|-seqpacket)?:(\w*):(\d+)$")


def _port(text: str) -> int | None:
    try:
        port = int(text)
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _ip_scope(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "network"
    return "loopback" if ip.is_loopback else "network"


def parse_listen(
    key: str,
    value: str,
    *,
    source: str,
    socket_protocol: str | None = None,
    loopback_only: bool = False,
) -> ListenAddress | None:
    """Parse one ``Listen*=`` value (specifiers already expanded); ``None`` if empty."""
    v = value.strip()
    if not v:
        return None
    if key in ("ListenFIFO", "ListenSpecial", "ListenMessageQueue", "ListenUSBFunction"):
        proto = "fifo" if key == "ListenFIFO" else "unknown"
        return ListenAddress(protocol=proto, path=v, scope="local", source=source)
    if key == "ListenNetlink":
        return ListenAddress(protocol="netlink", address=v, scope="local", source=source)
    if key == "ListenStream":
        ip_proto = socket_protocol if socket_protocol in ("sctp", "mptcp") else "tcp"
    elif key == "ListenDatagram":
        ip_proto = "udp"
    else:
        ip_proto = "sctp"
    if ip_proto == "mptcp":
        ip_proto = "tcp"
    if v.startswith(("/", "@")):
        return ListenAddress(protocol="unix", path=v, scope="local", source=source)
    m = _VSOCK_RE.match(v)
    if m:
        return ListenAddress(
            protocol="vsock",
            address=f"vsock:{m.group(1) or 'any'}",
            port=_port(m.group(2)),
            scope="local",
            source=source,
        )
    scope_override = "loopback" if loopback_only else None
    if v.isdigit():
        return ListenAddress(
            protocol=ip_proto,
            address=None,
            port=_port(v),
            scope=scope_override or "network",
            source=source,
        )
    m = _V4_RE.match(v) or _V6_RE.match(v)
    if m:
        addr = m.group(1)
        return ListenAddress(
            protocol=ip_proto,
            address=addr,
            port=_port(m.group(2)),
            scope=scope_override or _ip_scope(addr),
            source=source,
        )
    # unparseable: report conservatively as a network listener of unknown shape
    return ListenAddress(
        protocol="unknown", address=v, scope=scope_override or "network", source=source
    )


def loopback_restricted(
    ip_deny: list[str], ip_allow: list[str], bind_to_device: str | None
) -> bool:
    """True when socket-level settings confine an IP listener to loopback."""
    if (bind_to_device or "").strip() == "lo":
        return True
    deny_all = "any" in ip_deny or {"0.0.0.0/0", "::/0"} <= set(ip_deny)
    if not deny_all:
        return False
    if not ip_allow:
        return True  # nothing reachable at all; loopback is the conservative remainder
    for entry in ip_allow:
        if entry == "localhost":
            continue
        try:
            if not ipaddress.ip_network(entry, strict=False).is_loopback:
                return False
        except ValueError:
            return False
    return True
