"""Synthetic Report data and schema helpers shared by the report tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema

from startup_sbom.models import (
    SSVC,
    Activation,
    AttackChain,
    AttackStep,
    AttackTechnique,
    Binary,
    BlastRadius,
    Command,
    Consequence,
    ContainerInfo,
    Coverage,
    CVSSScore,
    EOLInfo,
    GraphEdge,
    GraphNode,
    Hardening,
    InitSystem,
    KEVInfo,
    LibraryLink,
    ListenAddress,
    OSInfo,
    Package,
    PackageType,
    Reachability,
    Report,
    ScanMetadata,
    Service,
    Severity,
    SSVCDecision,
    Summary,
    SupplyChain,
    SupplyChainFinding,
    TargetInfo,
    Threat,
    VendorSummary,
    Vulnerability,
    VulnStatus,
)

SCHEMAS = Path(__file__).parent / "schemas"

HOSTILE = "evil</script><script>alert(1)</script>[bold red]X[/] | `tick` \"q\" 's' --> <b>\nnext"

SSHD = "pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3?arch=amd64&distro=debian-12"
NGINX = "pkg:deb/debian/nginx@1.22.1-9?arch=amd64&distro=debian-12"
LIBSSL = (
    "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12"
    "&upstream=openssl%403.0.15-1~deb12u1"
)
LZMA = "pkg:deb/debian/liblzma5@5.4.1-0.2?arch=amd64&distro=debian-12&upstream=xz-utils"
LIBC64 = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=amd64&distro=debian-12&upstream=glibc"
LIBC32 = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u9?arch=i386&distro=debian-12&upstream=glibc"
SUDO = "pkg:deb/debian/sudo@1.9.13p3-1%2Bdeb12u1?arch=amd64&distro=debian-12"
LIBSYSTEMD = (
    "pkg:deb/debian/libsystemd0@252.30-1~deb12u2?arch=amd64&distro=debian-12&upstream=systemd"
)


def _pkg(pid: str, name: str, version: str, **kw: Any) -> Package:
    kw.setdefault("arch", "amd64")
    return Package(
        id=pid,
        purl=pid,
        type=PackageType.DEB,
        name=name,
        version=version,
        maintainer="Debian Maintainers <debian@example.org>",
        location="/var/lib/dpkg/status",
        **kw,
    )


def build_report(*, hostile: bool = False, container: bool = False) -> Report:
    """A small but complete Debian 12 report exercising every model section."""
    h = HOSTILE if hostile else ""
    packages = [
        _pkg(
            SSHD,
            "openssh-server",
            "1:9.2p1-2+deb12u3",
            source_name="openssh",
            source_version="1:9.2p1-2+deb12u3",
            license="BSD-2-Clause AND ISC",
            homepage="https://www.openssh.com/",
            depends=["libc6 (>= 2.36)", "libssl3 (>= 3.0.0)", "libsystemd0"],
            summary="secure shell (SSH) server" + h,
            file_count=42,
        ),
        _pkg(
            NGINX,
            "nginx" + (h if hostile else ""),
            "1.22.1-9",
            license="BSD-2-Clause",
            depends=["libc6", "libssl3 | libssl1.1"],
            repository="http://deb.debian.org/debian bookworm/main",
        ),
        _pkg(
            LIBSSL,
            "libssl3",
            "3.0.15-1~deb12u1",
            source_name="openssl",
            source_version="3.0.15-1~deb12u1",
            license="Apache-2.0",
            depends=["libc6"],
        ),
        _pkg(
            LZMA,
            "liblzma5",
            "5.4.1-0.2",
            source_name="xz-utils",
            source_version="5.4.1-0.2",
            license="PD-ish and GPL-2+" + h,
            depends=["libc6"],
            provenance_flags=["third_party_repo"],
            vendor="Tukaani" + h,
        ),
        _pkg(LIBC64, "libc6", "2.36-9+deb12u9", source_name="glibc", license="LGPL-2.1-or-later"),
        _pkg(
            LIBC32,
            "libc6",
            "2.36-9+deb12u9",
            arch="i386",
            source_name="glibc",
            license="LGPL-2.1-or-later",
        ),
        _pkg(
            SUDO,
            "sudo",
            "1.9.13p3-1+deb12u1",
            license="ISC",
            cpes=["cpe:2.3:a:sudo_project:sudo:1.9.13p3:*:*:*:*:*:*:*"],
        ),
        _pkg(
            LIBSYSTEMD,
            "libsystemd0",
            "252.30-1~deb12u2",
            source_name="systemd",
            depends=["liblzma5 (>= 5.1.1alpha+20120614)", "libc6"],
            license="LGPL-2.1-or-later",
        ),
    ]
    services = [
        Service(
            id="systemd:ssh.service",
            name="ssh.service",
            init_system=InitSystem.SYSTEMD,
            description="OpenBSD Secure Shell server" + h,
            unit_path="/lib/systemd/system/ssh.service",
            enabled=True,
            activation=[Activation.BOOT],
            boot_path=["default.target", "multi-user.target", "ssh.service"],
            commands=[
                Command(
                    directive="ExecStart",
                    argv=["/usr/sbin/sshd", "-D"],
                    raw="/usr/sbin/sshd -D $SSHD_OPTS",
                    executable="/usr/sbin/sshd",
                )
            ],
            executables=["/usr/sbin/sshd"],
            hardening=Hardening(user="root", exposure=9.6, exposure_rating="UNSAFE"),
            listens=[
                ListenAddress(protocol="tcp", address="0.0.0.0", port=22, source="sshd_config"),  # noqa: S104
                ListenAddress(protocol="tcp", address="::", port=22, source="sshd_config"),
            ],
            packages=[SSHD],
        ),
        Service(
            id="systemd:nginx.service" + h,
            name="nginx.service" + h,
            init_system=InitSystem.SYSTEMD,
            description="A high performance web server",
            enabled=True,
            activation=[Activation.BOOT],
            executables=["/usr/sbin/nginx"],
            hardening=Hardening(user="www-data", exposure=7.1, exposure_rating="EXPOSED"),
            listens=[
                ListenAddress(protocol="tcp", address="0.0.0.0", port=80, source="nginx.conf"),  # noqa: S104
                ListenAddress(protocol="unix", path="/run/nginx.sock", scope="local", source="x"),
            ],
            packages=[NGINX],
        ),
        Service(
            id="systemd:cron.service",
            name="cron.service",
            init_system=InitSystem.SYSTEMD,
            enabled=False,
            activation=[Activation.MANUAL],
        ),
    ]
    binaries = [
        Binary(
            path="/usr/sbin/sshd",
            package=SSHD,
            kind="elf",
            needed=["libssl.so.3", "libsystemd.so.0", "libc.so.6"],
            libraries=[
                LibraryLink(
                    soname="libssl.so.3",
                    path="/usr/lib/x86_64-linux-gnu/libssl.so.3",
                    package=LIBSSL,
                ),
                LibraryLink(
                    soname="libsystemd.so.0",
                    path="/usr/lib/x86_64-linux-gnu/libsystemd.so.0",
                    package=LIBSYSTEMD,
                ),
                LibraryLink(
                    soname="liblzma.so.5",
                    path="/usr/lib/x86_64-linux-gnu/liblzma.so.5",
                    package=LZMA,
                    depth=2,
                ),
            ],
            used_by=["systemd:ssh.service"],
        ),
        Binary(path="/usr/bin/sudo", package=SUDO, kind="elf", setuid=True, owner_uid=0),
    ]
    v31 = CVSSScore(
        version="3.1",
        vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=8.1,
        severity=Severity.HIGH,
        source="nvd",
    )
    v40 = CVSSScore(
        version="4.0",
        vector="CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        base_score=9.2,
        severity=Severity.CRITICAL,
    )
    vulns = [
        Vulnerability(
            id="CVE-2024-6387",
            aliases=["DEBIAN-CVE-2024-6387"],
            sources=["osv"],
            package=SSHD,
            package_name="openssh-server",
            installed_version="1:9.2p1-2+deb12u2",
            fixed_versions=["1:9.2p1-2+deb12u3"],
            summary="regreSSHion: signal handler race in sshd" + h,
            published="2024-07-01T13:15:00Z",
            modified="2024-07-10",
            severity=Severity.HIGH,
            cvss=[v31, v40],
            cwes=["CWE-364"],
            epss=0.43,
            epss_percentile=0.97,
            kev=KEVInfo(date_added="2025-01-01", due_date="2025-01-22", ransomware=False),
            references=["https://www.qualys.com/regresshion.txt"],
        ),
        Vulnerability(
            id="CVE-2024-3094",
            sources=["osv"],
            package=LZMA,
            package_name="liblzma5",
            installed_version="5.4.1-0.2",
            summary="xz backdoor" + h,
            severity=Severity.CRITICAL,
            cvss=[
                CVSSScore(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    base_score=10.0,
                    severity=Severity.CRITICAL,
                )
            ],
            cwes=["CWE-506"],
            epss=0.86,
            epss_percentile=0.99,
        ),
        Vulnerability(
            id="CVE-2023-0001",
            sources=["osv"],
            package=LIBC32,
            package_name="libc6",
            installed_version="2.36-9+deb12u9",
            summary="installed-only bug",
            severity=Severity.MEDIUM,
            cvss=[
                CVSSScore(
                    version="3.1",
                    vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    base_score=5.5,
                )
            ],
        ),
        Vulnerability(
            id="CVE-2023-0002",
            sources=["osv"],
            package=LIBC32,
            package_name="libc6",
            installed_version="2.36-9+deb12u9",
            summary="installed-only but KEV",
            severity=Severity.LOW,
            kev=KEVInfo(date_added="2024-02-02", ransomware=True),
        ),
        Vulnerability(
            id="CVE-2022-9999",
            sources=["osv"],
            package=NGINX,
            package_name="nginx",
            installed_version="1.22.1-9",
            status=VulnStatus.NOT_AFFECTED,
            summary="upstream says not affected",
        ),
        Vulnerability(
            id="CVE-2023-7777",
            sources=["osv"],
            package=SUDO,
            package_name="sudo",
            installed_version="1.9.13p3-1+deb12u1",
            summary="sudoedit privilege escalation",
            severity=Severity.HIGH,
            cvss=[
                CVSSScore(
                    version="3.0",
                    vector="CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    base_score=7.8,
                )
            ],
        ),
    ]
    rce = AttackTechnique(
        id="T1190", name="Exploit Public-Facing Application", tactic="initial-access"
    )
    pe = AttackTechnique(
        id="T1068", name="Exploitation for Privilege Escalation", tactic="privilege-escalation"
    )
    threats = [
        Threat(
            id="TH-0001",
            vulnerability="CVE-2024-6387",
            package=SSHD,
            title="Pre-auth RCE in network-exposed sshd" + h,
            reachability=Reachability.NETWORK_SERVICE,
            reachability_paths=[["systemd:ssh.service", "/usr/sbin/sshd", SSHD]],
            services=["systemd:ssh.service"],
            binaries=["/usr/sbin/sshd"],
            attack_vector="network",
            privileges_required="none",
            precondition="remote",
            postcondition="root",
            consequences=[Consequence.RCE],
            run_as="root",
            network_exposed=True,
            attack_techniques=[rce],
            ssvc=SSVC(
                exploitation="active",
                automatable="no",
                technical_impact="total",
                exposure="open",
                decision=SSVCDecision.ACT,
            ),
            risk_score=92.5,
            narrative="An unauthenticated remote attacker can race sshd's SIGALRM handler." + h,
            remediation="Upgrade openssh-server to 1:9.2p1-2+deb12u3.",
        ),
        Threat(
            id="TH-0002",
            vulnerability="CVE-2024-3094",
            package=LZMA,
            title="Backdoored liblzma loaded by sshd",
            reachability=Reachability.LINKED_BY_SERVICE,
            services=["systemd:ssh.service"],
            binaries=["/usr/sbin/sshd"],
            attack_vector="network",
            precondition="remote",
            postcondition="root",
            consequences=[Consequence.SUPPLY_CHAIN, Consequence.RCE],
            ssvc=SSVC(
                exploitation="public_poc",
                automatable="yes",
                technical_impact="total",
                exposure="open",
                decision=SSVCDecision.ATTEND,
            ),
            risk_score=88.0,
            narrative="liblzma is linked into sshd via libsystemd.",
        ),
        Threat(
            id="TH-0003",
            vulnerability="CVE-2023-0001",
            package=LIBC32,
            title="Installed-only libc6:i386 bug",
            reachability=Reachability.INSTALLED,
            attack_vector="local",
            precondition="local:any",
            postcondition="local:any",
            consequences=[Consequence.INFO_DISCLOSURE],
            ssvc=SSVC(
                exploitation="none",
                automatable="no",
                technical_impact="partial",
                exposure="small",
                decision=SSVCDecision.TRACK,
            ),
            risk_score=12.0,
            narrative="Not on any observed execution path.",
        ),
        Threat(
            id="TH-0004",
            vulnerability="CVE-2023-7777",
            package=SUDO,
            title="sudo setuid privilege escalation",
            reachability=Reachability.SETUID,
            binaries=["/usr/bin/sudo"],
            attack_vector="local",
            privileges_required="low",
            precondition="local:www-data",
            postcondition="root",
            consequences=[Consequence.PRIVESC],
            attack_techniques=[pe],
            ssvc=SSVC(
                exploitation="none",
                automatable="no",
                technical_impact="total",
                exposure="small",
                decision=SSVCDecision.TRACK_STAR,
            ),
            risk_score=55.0,
            narrative="A local user can escalate through sudoedit.",
        ),
    ]
    chains = [
        AttackChain(
            id="AC-0001",
            entry="remote",
            goal="root",
            steps=[
                AttackStep(
                    rule="network-rce",
                    title="Exploit nginx" + h,
                    from_state="remote",
                    to_state="local:www-data" + h,
                    technique=rce,
                    service="systemd:nginx.service" + h,
                    evidence=["nginx listens on 0.0.0.0:80" + h],
                    likelihood=0.6,
                ),
                AttackStep(
                    rule="setuid-privesc",
                    title="sudo privilege escalation",
                    from_state="local:www-data" + h,
                    to_state="root",
                    technique=pe,
                    threat="TH-0004",
                    vulnerability="CVE-2023-7777",
                    evidence=["/usr/bin/sudo is setuid root"],
                    mitigated_by=["NoNewPrivileges=yes would block this" + h],
                    likelihood=0.5,
                ),
            ],
            likelihood=0.3,
            impact=1.0,
            score=78.0,
            ssvc_decision=SSVCDecision.ATTEND,
            narrative="Remote attacker pivots from nginx to root via sudo." + h,
        ),
        AttackChain(
            id="AC-0002",
            entry="remote",
            goal="root",
            steps=[
                AttackStep(
                    rule="network-rce",
                    title="regreSSHion",
                    from_state="remote",
                    to_state="root",
                    technique=rce,
                    threat="TH-0001",
                    vulnerability="CVE-2024-6387",
                    service="systemd:ssh.service",
                    evidence=["sshd runs as root"],
                    likelihood=0.4,
                )
            ],
            likelihood=0.4,
            impact=1.0,
            score=90.0,
            ssvc_decision=SSVCDecision.ACT,
            narrative="Direct root via sshd.",
        ),
    ]
    supply = SupplyChain(
        vendors=[
            VendorSummary(vendor="Debian Project", packages=7, boot_packages=4, services=2),
            VendorSummary(vendor="Tukaani" + h, packages=1, vulnerabilities=1, critical=1),
        ],
        findings=[
            SupplyChainFinding(
                id="SC-0001",
                kind="third_party_repo",
                severity=Severity.MEDIUM,
                subject=LZMA,
                title="Package from a third-party repository" + h,
                detail="liblzma5 came from an unofficial source",
                evidence=["/etc/apt/sources.list.d/xz.list"],
            ),
            SupplyChainFinding(
                id="SC-0002",
                kind="unmanaged_binary",
                severity=Severity.HIGH,
                subject="/usr/local/bin/agent",
                title="Unmanaged executable started at boot",
            ),
        ],
        blast_radius=[
            BlastRadius(
                package=LZMA,
                vendor="Tukaani" + h,
                services=["systemd:ssh.service"],
                binaries=["/usr/sbin/sshd"],
                example_paths=[[LZMA, LIBSYSTEMD, "/usr/sbin/sshd", "systemd:ssh.service"]],
                vulnerabilities=["CVE-2024-3094"],
                score=95.0,
            )
        ],
        nodes=[
            GraphNode(id=LZMA, kind="package", label="liblzma5" + h),
            GraphNode(id="systemd:ssh.service", kind="service", label="ssh.service"),
        ],
        edges=[GraphEdge(source=LZMA, target="systemd:ssh.service", kind="loads")],
    )
    return Report(
        metadata=ScanMetadata(
            tool_version="2.0.0",
            scan_id="7f1d1c5e-2c0a-4e57-9c51-3a9d0b8f4e21",
            started=datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC),
            finished=datetime(2026, 10, 10, 12, 0, 5, tzinfo=UTC),
            target=TargetInfo(kind="dir", reference="/mnt/rootfs" + h),
            coverage=Coverage(
                package_databases=["dpkg"],
                init_systems=["systemd"],
                vulnerability_sources=["osv", "epss", "kev"],
                vulnerability_ecosystems=["Debian:12"],
                limitations=["Socket activation not fully modelled" + h],
            ),
        ),
        os=OSInfo(
            id="debian",
            id_like=[],
            name="Debian GNU/Linux",
            pretty_name="Debian GNU/Linux 12 (bookworm)" + h,
            version_id="12",
            version_codename="bookworm",
            family="debian",
            vuln_ecosystems=["Debian:12"],
            eol=EOLInfo(
                product="debian", cycle="12", eol_date="2026-06-10", is_eol=True, lts=False
            ),
        ),
        container=(
            ContainerInfo(
                kind="image",
                engine="docker",
                image="docker.io/library/nginx:1.25",
                image_digest="sha256:" + "a" * 64,
                user="root",
                exposed_ports=["80/tcp"],
                env_keys=["PATH", "API_TOKEN"],
                redacted_env_keys=["API_TOKEN"],
            )
            if container
            else None
        ),
        summary=Summary(
            packages=len(packages),
            boot_packages=4,
            services=3,
            boot_services=2,
            network_services=2,
            vulnerabilities=len(vulns),
            by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1, "unknown": 1},
            kev=2,
            threats=len(threats),
            act=1,
            attend=1,
            attack_chains=2,
            supply_chain_findings=2,
        ),
        packages=packages,
        services=services,
        binaries=binaries,
        vulnerabilities=vulns,
        threats=threats,
        attack_chains=chains,
        supply_chain=supply,
        warnings=["Could not read /etc/shadow" + h],
    )


def validate_schema(doc: object, schema_file: str) -> None:
    """Validate ``doc`` against a vendored schema; fail with all error messages."""
    schema = json.loads((SCHEMAS / schema_file).read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    validator = cls(schema, format_checker=cls.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(doc), key=str)
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message[:300]}" for e in errors)
