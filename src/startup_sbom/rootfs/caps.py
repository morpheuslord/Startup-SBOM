"""Decoding of Linux file capabilities (``security.capability`` xattr)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

CAP_NAMES = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid",
    "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast",
    "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
    "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
    "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
    "audit_control", "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
)  # fmt: skip

#: Capabilities that are equivalent (or nearly) to full root.
DANGEROUS_CAPS = frozenset(
    {
        "sys_admin", "sys_module", "sys_ptrace", "sys_rawio", "dac_override",
        "dac_read_search", "setuid", "setgid", "setfcap", "setpcap", "chown",
        "fowner", "bpf", "net_admin", "sys_boot", "mknod",
    }
)  # fmt: skip

_REVISION_MASK = 0xFF000000
_FLAG_EFFECTIVE = 0x000001


@dataclass(frozen=True, slots=True)
class FileCaps:
    """Decoded ``vfs_cap_data`` / ``vfs_ns_cap_data``."""

    revision: int
    effective: bool
    permitted: frozenset[str]
    inheritable: frozenset[str]
    rootid: int | None = None

    @property
    def all(self) -> frozenset[str]:
        return self.permitted | self.inheritable

    @property
    def dangerous(self) -> frozenset[str]:
        return self.permitted & DANGEROUS_CAPS

    def __str__(self) -> str:
        caps = ",".join("cap_" + c for c in sorted(self.all))
        flags = (
            ("e" if self.effective else "")
            + ("p" if self.permitted else "")
            + ("i" if self.inheritable else "")
        )
        return f"{caps}={flags}"


def _bits(value: int) -> frozenset[str]:
    return frozenset(
        CAP_NAMES[i] if i < len(CAP_NAMES) else f"cap{i}" for i in range(64) if value >> i & 1
    )


def decode_vfs_cap(raw: bytes) -> FileCaps | None:
    """Decode ``security.capability`` (little endian); ``None`` if malformed."""
    if len(raw) < 4:
        return None
    (magic,) = struct.unpack_from("<I", raw, 0)
    rev = (magic & _REVISION_MASK) >> 24
    eff = bool(magic & _FLAG_EFFECTIVE)
    if rev == 1 and len(raw) >= 12:
        p, i = struct.unpack_from("<II", raw, 4)
        return FileCaps(1, eff, _bits(p), _bits(i))
    if rev in (2, 3) and len(raw) >= 20:
        p0, i0, p1, i1 = struct.unpack_from("<IIII", raw, 4)
        rootid = struct.unpack_from("<I", raw, 20)[0] if rev == 3 and len(raw) >= 24 else None
        return FileCaps(rev, eff, _bits(p0 | p1 << 32), _bits(i0 | i1 << 32), rootid)
    return None
