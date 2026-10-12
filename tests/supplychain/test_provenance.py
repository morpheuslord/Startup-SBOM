"""Provenance findings, integrity verification and vendor normalisation."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest
from sc_helpers import pkg, report, service

from fsbuilder import File
from startup_sbom.context import ScanContext
from startup_sbom.models import Binary, EOLInfo, OSInfo, PackageType, Severity
from startup_sbom.pkgdb.base import PackageRecord
from startup_sbom.pkgdb.ownership import FileOwnerIndex
from startup_sbom.rootfs import RootFS
from startup_sbom.supplychain import analyze
from startup_sbom.supplychain.integrity import parse_digest
from startup_sbom.supplychain.provenance import compromised_release, finding_id, upstream_version
from startup_sbom.supplychain.repos import DISTRO_TRUST
from startup_sbom.supplychain.vendors import vendor_of


@pytest.mark.parametrize(
    ("name", "version", "flagged"),
    [
        ("liblzma5", "5.6.1-1", True),
        ("xz-utils", "5.6.0-0.2", True),
        ("xz-libs", "1:5.6.0-1.fc40", True),
        ("xz", "5.6.1-r0", True),
        ("liblzma5", "5.6.1+really5.4.5-1", False),
        ("xz-utils", "5.6.1+really5.4.5-1ubuntu0.3", False),
        ("liblzma5", "5.6.10-1", False),
        ("liblzma5", "5.4.5-0.3", False),
        ("zlib", "5.6.1-1", False),
    ],
)
def test_suspicious_version_respects_really(name: str, version: str, flagged: bool) -> None:
    assert (compromised_release(pkg(name, version)) is not None) is flagged


def test_upstream_version() -> None:
    assert upstream_version("1:9.7p1-2") == "9.7p1"
    assert upstream_version("5.6.1+really5.4.5-1") == "5.4.5"


def test_finding_ids_are_stable() -> None:
    assert finding_id("unmanaged_binary", "/x") == finding_id("unmanaged_binary", "/x")
    assert finding_id("unmanaged_binary", "/x") != finding_id("modified_file", "/x")


def test_parse_digest_hex_and_base64() -> None:
    md5 = hashlib.md5(b"x", usedforsecurity=False)
    assert parse_digest(f"md5:{md5.hexdigest()}") == ("md5", md5.hexdigest())
    import base64

    sha1 = hashlib.sha1(b"x", usedforsecurity=False)
    b64 = base64.b64encode(sha1.digest()).decode()
    assert parse_digest(f"sha1:{b64}") == ("sha1", sha1.hexdigest())
    assert parse_digest("crc32:abcd") is None
    assert parse_digest("garbage") is None


def test_vendor_normalisation() -> None:
    debian = DISTRO_TRUST["debian"]
    team = pkg(
        "udev", "1", maintainer="Debian systemd Maintainers <pkg-systemd@lists.alioth.debian.org>"
    )
    person = pkg("liblzma5", "1", maintainer="Sebastian Andrzej Siewior <sebastian@breakpoint.cc>")
    ubuntu = pkg(
        "bash", "1", maintainer="Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"
    )
    third = pkg(
        "docker-ce",
        "1",
        maintainer="Docker <support@docker.com>",
        provenance_flags=["third_party_repo"],
    )
    aur = pkg("yay", "1", PackageType.ALPM, packager="Unknown Packager")
    rpm = pkg("bash", "1", PackageType.RPM, vendor="Fedora Project", packager="Fedora Project")
    copr = pkg("x", "1", PackageType.RPM, vendor="Fedora Copr - user ublue-os")
    assert vendor_of(team, debian) == "Debian"
    assert vendor_of(person, debian) == "Debian"
    assert vendor_of(ubuntu, debian) == "Ubuntu"
    assert vendor_of(third, debian) == "Docker"
    assert vendor_of(aur, None) == "local build"
    assert vendor_of(rpm, None) == "Fedora Project"
    assert vendor_of(copr, None) == "Fedora Copr - user ublue-os"


def test_unmanaged_binary_used_by_service_is_high(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_dir_fs(
        {
            "/opt/agent/bin/agentd": File(b"\x7fELF", mode=0o755),
            "/usr/local/bin/helper": File(b"#!/bin/sh\n", mode=0o755),
            "/tmp/.x/miner": File(b"\x7fELF", mode=0o755),
        }
    )
    ctx = make_ctx(fs)
    rep = report(
        [],
        services=[service("agent.service", "/opt/agent/bin/agentd")],
        binaries=[Binary(path="/opt/agent/bin/agentd", used_by=["systemd:agent.service"])],
    )
    sc = analyze(
        rep,
        [],
        ctx,
        FileOwnerIndex(fs),
        unmanaged_executables=["/opt/agent/bin/agentd", "/usr/local/bin/helper", "/tmp/.x/miner"],
    )
    by_subject = {(f.kind, f.subject): f for f in sc.findings}
    agent = by_subject[("unmanaged_binary", "/opt/agent/bin/agentd")]
    assert agent.severity is Severity.HIGH
    assert "systemd:agent.service" in agent.evidence[0]
    assert by_subject[("unmanaged_binary", "/tmp/.x/miner")].severity is Severity.MEDIUM
    summary = by_subject[("unmanaged_binary", "system")]
    assert summary.severity is Severity.LOW
    assert summary.evidence == ["/usr/local/bin/helper"]


def test_integrity_mismatch_and_conffile_skip(
    make_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    good = b"\x7fELF genuine sshd"
    fs = make_fs(
        {
            "/usr/sbin/sshd": File(b"\x7fELF backdoored sshd", mode=0o755),
            "/usr/sbin/sshd-session": File(good, mode=0o755),
            "/etc/ssh/sshd_config": "PermitRootLogin no\n",
            "/bin": "placeholder",
        }
    )
    ctx = make_ctx(fs, integrity_check=True)
    ssh = pkg("openssh-server", "1:9.2p1-2")
    md5 = hashlib.md5(good, usedforsecurity=False).hexdigest()
    rec = PackageRecord(
        package=ssh,
        files=["/usr/sbin/sshd", "/usr/sbin/sshd-session", "/etc/ssh/sshd_config"],
        digests={
            "/usr/sbin/sshd": f"md5:{md5}",
            "/usr/sbin/sshd-session": f"md5:{md5}",
            "/etc/ssh/sshd_config": "md5:00000000000000000000000000000000",
        },
        conffiles=["/etc/ssh/sshd_config"],
    )
    owners = FileOwnerIndex(fs)
    owners.add_records([rec])
    svc = service("ssh.service", "/usr/sbin/sshd", network=True, packages=[ssh.id])
    svc.executables.append("/usr/sbin/sshd-session")
    svc.executables.append("/etc/ssh/sshd_config")  # hostile/odd input: must be skipped
    rep = report([ssh], services=[svc])
    sc = analyze(rep, [rec], ctx, owners)
    modified = [f for f in sc.findings if f.kind == "modified_file"]
    assert len(modified) == 1
    assert modified[0].subject == ssh.id
    assert modified[0].severity is Severity.HIGH
    assert len(modified[0].evidence) == 1
    assert modified[0].evidence[0].startswith("/usr/sbin/sshd: md5")
    assert "modified_file" in ssh.provenance_flags
    radius = {b.package: b for b in sc.blast_radius}
    assert radius[ssh.id].services == ["systemd:ssh.service"]


def test_integrity_disabled_by_default(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_dir_fs({"/usr/sbin/sshd": File(b"changed", mode=0o755)})
    ctx = make_ctx(fs)
    ssh = pkg("openssh-server", "1")
    rec = PackageRecord(
        package=ssh, files=["/usr/sbin/sshd"], digests={"/usr/sbin/sshd": "md5:" + "0" * 32}
    )
    owners = FileOwnerIndex(fs)
    owners.add_records([rec])
    rep = report([ssh], services=[service("ssh.service", "/usr/sbin/sshd")])
    sc = analyze(rep, [rec], ctx, owners)
    assert not [f for f in sc.findings if f.kind == "modified_file"]


def test_eol_and_language_and_third_party_findings(
    make_dir_fs: Callable[[dict[str, object]], RootFS], make_ctx: Callable[..., ScanContext]
) -> None:
    fs = make_dir_fs(
        {
            "/etc/apt/sources.list": (
                "deb http://archive.debian.org/debian buster main\n"
                "deb https://download.docker.com/linux/debian buster stable\n"
            ),
            "/var/lib/apt/lists/download.docker.com_linux_debian_dists_buster_stable_binary-"
            "amd64_Packages": ("Package: containerd.io\nVersion: 1.6.0-1\nArchitecture: amd64\n"),
        }
    )
    ctx = make_ctx(fs)
    ctx.os = OSInfo(id="debian", version_id="10", family="debian")
    containerd = pkg("containerd.io", "1.6.0-1", maintainer="Containerd team <help@containerd.io>")
    requests = pkg(
        "requests", "2.31.0", PackageType.PYPI, location="/usr/lib/python3/dist-packages"
    )
    rep = report(
        [containerd, requests],
        services=[service("containerd.service", "/usr/bin/containerd", packages=[containerd.id])],
        binaries=[
            Binary(
                path="/usr/bin/containerd",
                package=containerd.id,
                used_by=["systemd:containerd.service"],
            )
        ],
    )
    rep.os = ctx.os.model_copy(
        update={"eol": EOLInfo(product="debian", cycle="10", eol_date="2024-06-30", is_eol=True)}
    )
    sc = analyze(rep, [], ctx, FileOwnerIndex(fs))
    kinds = {f.kind: f for f in sc.findings}
    assert kinds["eol_distro"].severity is Severity.HIGH
    assert kinds["embedded_language_packages"].severity is Severity.NONE
    tp = kinds["third_party_repo"]
    assert tp.severity is Severity.MEDIUM
    assert tp.subject == "repo:download.docker.com/linux/debian buster/stable"
    assert any(e.startswith("boot package containerd.io") for e in tp.evidence)
    assert containerd.repository == "download.docker.com/linux/debian buster/stable"
    assert {v.vendor for v in sc.vendors} >= {"Containerd team"}
    assert [f.severity.rank for f in sc.findings] == sorted(
        (f.severity.rank for f in sc.findings), reverse=True
    )
