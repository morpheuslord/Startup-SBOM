"""The regreSSHion + pkexec worked example as a fully analysed in-memory report."""

from __future__ import annotations

from datetime import UTC, datetime

import factory as F  # noqa: N812 - the shared threat-test factory

from startup_sbom.context import ScanContext
from startup_sbom.models import ExploitRef, Hardening, IntelBundle, Report
from startup_sbom.threat import build_attack_chains, reverse_vulnerabilities

#: CVE-2024-6387 (regreSSHion): unauthenticated RCE as root in sshd, AC:H.
SSHD_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
#: CVE-2021-4034 (PwnKit): local privilege escalation through setuid pkexec.
PWNKIT_VECTOR = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
EPOCH = datetime(2026, 10, 10, 0, 0, 0, tzinfo=UTC)


def regresshion_pkexec(ctx: ScanContext, *, kev_sshd: bool = False) -> Report:
    """A root sshd listening on :22 (regreSSHion) plus a vulnerable setuid pkexec."""
    openssh = F.pkg("openssh-server", "1:9.2p1-2+deb12u2")
    polkit = F.pkg("policykit-1", "122-3")
    sshd = F.binary("/usr/sbin/sshd", package=openssh.id, used_by=["systemd:ssh"])
    pkexec = F.binary("/usr/bin/pkexec", package=polkit.id, setuid=True, owner_uid=0)
    svc = F.service(
        "ssh",
        executables=["/usr/sbin/sshd"],
        packages=[openssh.id],
        listens=[F.tcp(22)],
        hardening=Hardening(user="root"),
    )
    v_ssh = F.vuln(
        "CVE-2024-6387",
        openssh,
        fixed=["1:9.2p1-2+deb12u3"],
        cvss_scores=[F.cvss(SSHD_VECTOR, 8.1)],
        cwes=["CWE-364"],
        epss=0.72,
        kev=kev_sshd,
        summary="signal handler race condition in sshd allows unauthenticated RCE as root",
    )
    v_pk = F.vuln(
        "CVE-2021-4034",
        polkit,
        fixed=["122-4"],
        cvss_scores=[F.cvss(PWNKIT_VECTOR, 7.8)],
        cwes=["CWE-787"],
        epss=0.9,
        kev=True,
        summary="pkexec argument handling allows any local user to gain root",
    )
    report = F.make_report(
        packages=[openssh, polkit],
        services=[svc],
        binaries=[sshd, pkexec],
        vulnerabilities=[v_ssh, v_pk],
    )
    report.threats = reverse_vulnerabilities(report, ctx)
    report.attack_chains = build_attack_chains(report, report.threats, ctx)
    report.summary.threats = len(report.threats)
    return report


def sshd_intel(*, exploitation: str = "active", maturity: str = "weaponized") -> IntelBundle:
    """Prefetched exploit intelligence for CVE-2024-6387."""
    return IntelBundle(
        cve="CVE-2024-6387",
        exploit_maturity=maturity,
        exploitation=exploitation,
        exploit_available=True,
        exploit_sources=["metasploit", "exploitdb"],
        metasploit=[ExploitRef(source="metasploit", id="exploit/linux/ssh/regresshion")],
        exploitdb=[
            ExploitRef(source="exploitdb", id="52100"),
            ExploitRef(source="exploitdb", id="52101"),
        ],
        poc_repos_count=88,
        fetched_at=EPOCH,
    )
