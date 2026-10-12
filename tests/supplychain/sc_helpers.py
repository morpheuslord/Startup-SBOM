"""Builders for hand-made reports and OpenPGP keys used by the supply-chain tests."""

from __future__ import annotations

import base64
import hashlib
import struct
from datetime import UTC, datetime
from typing import Any

from startup_sbom.models import (
    Activation,
    Binary,
    Confidence,
    Hardening,
    InitSystem,
    KEVInfo,
    LibraryLink,
    ListenAddress,
    OSInfo,
    Package,
    PackageType,
    Report,
    ScanMetadata,
    Service,
    Severity,
    TargetInfo,
    Vulnerability,
)

LIB = "/usr/lib/x86_64-linux-gnu"


def pkg(name: str, version: str, ptype: PackageType = PackageType.DEB, **kw: Any) -> Package:
    distro = {"deb": "debian", "rpm": "fedora", "apk": "alpine", "alpm": "arch"}.get(
        ptype.value, "generic"
    )
    arch = kw.pop("arch", "amd64" if ptype is PackageType.DEB else "x86_64")
    purl = f"pkg:{ptype.value}/{distro}/{name}@{version}?arch={arch}"
    return Package(
        id=kw.pop("id", purl), type=ptype, name=name, version=version, arch=arch, purl=purl, **kw
    )


def report(
    packages: list[Package],
    services: list[Service] | None = None,
    binaries: list[Binary] | None = None,
    vulns: list[Vulnerability] | None = None,
    os_id: str = "debian",
) -> Report:
    return Report(
        metadata=ScanMetadata(
            tool_version="2.0.0",
            scan_id="test",
            started=datetime(2026, 10, 10, tzinfo=UTC),
            target=TargetInfo(kind="dir", reference="/target"),
        ),
        os=OSInfo(id=os_id, version_id="13", family="debian" if os_id == "debian" else None),
        packages=packages,
        services=services or [],
        binaries=binaries or [],
        vulnerabilities=vulns or [],
    )


def service(
    name: str,
    exe: str,
    *,
    network: bool = False,
    auto: bool = True,
    packages: list[str] | None = None,
) -> Service:
    return Service(
        id=f"systemd:{name}",
        name=name,
        init_system=InitSystem.SYSTEMD,
        enabled=auto,
        activation=[Activation.BOOT] if auto else [Activation.MANUAL],
        executables=[exe],
        hardening=Hardening(user="root"),
        listens=[ListenAddress(protocol="tcp", port=22, source="unit")] if network else [],
        packages=packages or [],
    )


def link(
    soname: str, path: str, package: str | None, depth: int = 1, via: str = "needed"
) -> LibraryLink:
    return LibraryLink(
        soname=soname,
        path=path,
        package=package,
        depth=depth,
        via=via,
        confidence=Confidence.HIGH,
    )


def vuln(package: Package, vid: str, severity: Severity, kev: bool = False) -> Vulnerability:
    return Vulnerability(
        id=vid,
        package=package.id,
        package_name=package.name,
        installed_version=package.version,
        severity=severity,
        kev=KEVInfo(date_added="2024-03-29") if kev else None,
    )


def xz_report(*, libsystemd_record: bool, extra_direct: bool = False) -> Report:
    """Debian sid, March 2024: sshd → libsystemd → liblzma, no package Depends at all."""
    liblzma = pkg(
        "liblzma5",
        "5.6.1-1",
        source_name="xz-utils",
        maintainer="Sebastian Andrzej Siewior <sebastian@breakpoint.cc>",
    )
    libsystemd = pkg(
        "libsystemd0",
        "255.4-1",
        source_name="systemd",
        maintainer="Debian systemd Maintainers <pkg-systemd-maintainers@lists.alioth.debian.org>",
    )
    openssh = pkg(
        "openssh-server",
        "1:9.7p1-2",
        source_name="openssh",
        maintainer="Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>",
    )
    libc = pkg(
        "libc6",
        "2.37-15",
        source_name="glibc",
        maintainer="GNU Libc Maintainers <debian-glibc@lists.debian.org>",
    )
    cron = pkg("cron", "3.0pl1-184", maintainer="Debian Cron Team <cron@packages.debian.org>")
    sshd_libs = [link("libsystemd.so.0", f"{LIB}/libsystemd.so.0", libsystemd.id)]
    if extra_direct:
        sshd_libs.insert(0, link("libc.so.6", f"{LIB}/libc.so.6", libc.id))
    sshd_libs.append(link("liblzma.so.5", f"{LIB}/liblzma.so.5", liblzma.id, depth=2))
    binaries = [
        Binary(
            path="/usr/sbin/sshd",
            package=openssh.id,
            kind="elf",
            libraries=sshd_libs,
            used_by=["systemd:ssh.service"],
        ),
        Binary(
            path="/usr/sbin/cron",
            package=cron.id,
            kind="elf",
            libraries=[link("libc.so.6", f"{LIB}/libc.so.6", libc.id)],
            used_by=["systemd:cron.service"],
        ),
    ]
    if libsystemd_record:
        binaries.append(
            Binary(
                path=f"{LIB}/libsystemd.so.0",
                package=libsystemd.id,
                kind="elf",
                needed=["liblzma.so.5", "libc.so.6"],
                libraries=[
                    link("liblzma.so.5", f"{LIB}/liblzma.so.5", liblzma.id),
                    link("libc.so.6", f"{LIB}/libc.so.6", libc.id),
                ],
            )
        )
    return report(
        [openssh, libsystemd, liblzma, libc, cron],
        services=[
            service("ssh.service", "/usr/sbin/sshd", network=True, packages=[openssh.id]),
            service("cron.service", "/usr/sbin/cron", packages=[cron.id]),
        ],
        binaries=binaries,
        vulns=[vuln(liblzma, "CVE-2024-3094", Severity.CRITICAL, kev=True)],
    )


# --------------------------------------------------------------------------- OpenPGP
def _mpi(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return struct.pack(">H", value.bit_length()) + raw


def _packet(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag, 255]) + struct.pack(">I", len(body)) + body


def make_pgp_key(uid: str, seed: int) -> tuple[str, str, bytes]:
    """Return ``(key_id, fingerprint, armored)`` of a syntactically valid v4 RSA key."""
    n = int.from_bytes(hashlib.sha512(str(seed).encode()).digest() * 4, "big") | 1
    body = b"\x04" + struct.pack(">I", 1_700_000_000 + seed) + b"\x01" + _mpi(n) + _mpi(65537)
    fp = hashlib.sha1(
        b"\x99" + struct.pack(">H", len(body)) + body, usedforsecurity=False
    ).hexdigest()
    data = _packet(6, body) + _packet(13, uid.encode())
    b64 = base64.b64encode(data).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    armored = "\n".join(
        [
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "Version: test",
            "",
            *lines,
            "=abcd",
            "-----END PGP PUBLIC KEY BLOCK-----",
            "",
        ]
    )
    return fp[-16:], fp, armored.encode()
