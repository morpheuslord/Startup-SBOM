"""Vulnerability → threat reversal, reproducing the research worked examples."""

from __future__ import annotations

import factory as F  # noqa: N812

from startup_sbom.context import ScanContext
from startup_sbom.models import (
    Activation,
    Consequence,
    Hardening,
    Reachability,
    SSVCDecision,
    VulnStatus,
)
from startup_sbom.threat import reverse_vulnerabilities

REGRESSHION = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
PWNKIT = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
DIRTYPIPE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
XZ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _one(report: object, ctx: ScanContext):  # type: ignore[no-untyped-def]
    threats = reverse_vulnerabilities(report, ctx)  # type: ignore[arg-type]
    assert threats
    return threats[0]


def test_regresshion_network_service_remote_to_root(ctx: ScanContext) -> None:
    p = F.pkg("openssh-server", "1:9.6p1-3")
    b = F.binary("/usr/sbin/sshd", package=p.id, used_by=["systemd:ssh"])
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[p.id], listens=[F.tcp(22)])
    v = F.vuln(
        "CVE-2024-6387",
        p,
        fixed=["1:9.6p1-5"],
        cvss_scores=[F.cvss(REGRESSHION, 8.1)],
        cwes=["CWE-364"],
        epss=0.995,
    )
    t = _one(F.make_report(packages=[p], services=[svc], binaries=[b], vulnerabilities=[v]), ctx)

    assert t.reachability is Reachability.NETWORK_SERVICE
    assert t.precondition == "remote"
    assert t.postcondition == "root"
    assert t.run_as == "root"
    assert t.network_exposed
    assert t.reachability_paths[0] == ["systemd:ssh", "/usr/sbin/sshd", p.id]
    assert any(x.id == "T1190" for x in t.attack_techniques)
    # KEV absent, EPSS high → public_poc; AC:H ⇒ not automatable ⇒ Attend (not Act).
    assert t.ssvc is not None
    assert t.ssvc.exploitation == "public_poc"
    assert t.ssvc.automatable == "no"
    assert t.ssvc.exposure == "open"
    assert t.ssvc.decision in (SSVCDecision.ATTEND, SSVCDecision.ACT)
    assert t.remediation is not None
    assert "9.6p1-5" in t.remediation
    assert "Evidence:" in t.narrative


def test_xz_linked_by_service_full_path(ctx: ScanContext) -> None:
    pssh = F.pkg("openssh-server", "1:9.6p1-3")
    psysd = F.pkg("libsystemd0", "255.4-1")
    plz = F.pkg("liblzma5", "5.6.1-1")
    sshd = F.binary(
        "/usr/sbin/sshd",
        package=pssh.id,
        used_by=["systemd:ssh"],
        libraries=[
            F.lib(
                "libsystemd.so.0", "/usr/lib/x86_64-linux-gnu/libsystemd.so.0", psysd.id, depth=1
            ),
            F.lib("liblzma.so.5", "/usr/lib/x86_64-linux-gnu/liblzma.so.5", plz.id, depth=2),
        ],
    )
    libsd = F.binary(
        "/usr/lib/x86_64-linux-gnu/libsystemd.so.0",
        package=psysd.id,
        libraries=[F.lib("liblzma.so.5", "/usr/lib/x86_64-linux-gnu/liblzma.so.5", plz.id)],
    )
    liblz = F.binary("/usr/lib/x86_64-linux-gnu/liblzma.so.5", package=plz.id)
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[pssh.id], listens=[F.tcp(22)])
    v = F.vuln(
        "CVE-2024-3094", plz, cvss_scores=[F.cvss(XZ, 10.0)], cwes=["CWE-506"], epss=0.6, kev=True
    )
    t = _one(
        F.make_report(
            packages=[pssh, psysd, plz],
            services=[svc],
            binaries=[sshd, libsd, liblz],
            vulnerabilities=[v],
        ),
        ctx,
    )

    assert t.reachability is Reachability.LINKED_BY_SERVICE
    assert t.reachability_paths[0] == [
        "systemd:ssh",
        "/usr/sbin/sshd",
        "/usr/lib/x86_64-linux-gnu/libsystemd.so.0",
        "/usr/lib/x86_64-linux-gnu/liblzma.so.5",
        plz.id,
    ]
    assert Consequence.SUPPLY_CHAIN in t.consequences
    assert t.precondition == "remote"
    assert t.postcondition == "root"
    # KEV active + automatable + total + open ⇒ Act.
    assert t.ssvc is not None
    assert t.ssvc.decision is SSVCDecision.ACT


def test_xz_dlopen_variant_lower_confidence(ctx: ScanContext) -> None:
    pssh = F.pkg("openssh-server", "1:9.6p1-3")
    plz = F.pkg("liblzma5", "5.6.1-1")
    sshd = F.binary(
        "/usr/sbin/sshd",
        package=pssh.id,
        used_by=["systemd:ssh"],
        libraries=[F.lib("liblzma.so.5", "/usr/lib/liblzma.so.5", plz.id, via="dlopen")],
    )
    liblz = F.binary("/usr/lib/liblzma.so.5", package=plz.id)
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[pssh.id], listens=[F.tcp(22)])
    v = F.vuln("CVE-2024-3094", plz, cvss_scores=[F.cvss(XZ, 10.0)], cwes=["CWE-506"], kev=True)
    t = _one(
        F.make_report(
            packages=[pssh, plz], services=[svc], binaries=[sshd, liblz], vulnerabilities=[v]
        ),
        ctx,
    )
    assert t.reachability is Reachability.LINKED_BY_SERVICE
    assert "dlopen" in " ".join(t.narrative.splitlines())


def test_pkexec_setuid_local_to_root(ctx: ScanContext) -> None:
    p = F.pkg("policykit-1", "0.105-31")
    b = F.binary("/usr/bin/pkexec", package=p.id, setuid=True, owner_uid=0)
    v = F.vuln(
        "CVE-2021-4034",
        p,
        fixed=["0.105-31.1"],
        cvss_scores=[F.cvss(PWNKIT, 7.8)],
        cwes=["CWE-787"],
        epss=0.94,
        kev=True,
    )
    t = _one(F.make_report(packages=[p], binaries=[b], vulnerabilities=[v]), ctx)
    assert t.reachability is Reachability.SETUID
    assert t.precondition == "local"
    assert t.postcondition == "root"
    assert any(x.id == "T1068" for x in t.attack_techniques)
    assert t.ssvc is not None
    assert t.ssvc.exploitation == "active"


def test_dirtypipe_kernel_local_to_root(ctx: ScanContext) -> None:
    p = F.pkg("linux-image-6.1.0-10-amd64", "6.1.38-1")
    v = F.vuln(
        "CVE-2022-0847",
        p,
        fixed=["6.1.38-2"],
        cvss_scores=[F.cvss(DIRTYPIPE, 7.8)],
        cwes=["CWE-665"],
        epss=0.5,
        kev=True,
    )
    t = _one(F.make_report(packages=[p], vulnerabilities=[v]), ctx)
    assert t.reachability is Reachability.KERNEL
    assert t.postcondition == "root"
    assert t.precondition.startswith("local")


def test_installed_only_low_score_track(ctx: ScanContext) -> None:
    p = F.pkg("libfoo", "1.0-1")
    b = F.binary("/usr/lib/libfoo.so.1", package=p.id)  # linked by nothing
    v = F.vuln(
        "CVE-2024-11111",
        p,
        cvss_scores=[F.cvss("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.8)],
        cwes=["CWE-200"],
        epss=0.001,
    )
    t = _one(F.make_report(packages=[p], binaries=[b], vulnerabilities=[v]), ctx)
    assert t.reachability is Reachability.INSTALLED
    assert t.risk_score < 15.0
    assert t.ssvc is not None
    assert t.ssvc.decision is SSVCDecision.TRACK
    # Disclosure-only: attacker state does not advance.
    assert t.postcondition == t.precondition


def test_missing_cvss_is_conservative_no_crash(ctx: ScanContext) -> None:
    p = F.pkg("openssh-server", "1:9.6p1-3")
    b = F.binary("/usr/sbin/sshd", package=p.id, used_by=["systemd:ssh"])
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[p.id], listens=[F.tcp(22)])
    v = F.vuln("CVE-2099-0001", p)  # no CVSS, no CWE, no EPSS
    t = _one(F.make_report(packages=[p], services=[svc], binaries=[b], vulnerabilities=[v]), ctx)
    assert t.attack_vector == "unknown"
    assert t.privileges_required == "unknown"
    assert t.consequences  # still records something (OTHER at worst)
    assert t.score_factors["exploitability_unknown"] == 1.0
    assert t.ssvc is not None


def test_fixed_and_not_affected_are_skipped(ctx: ScanContext) -> None:
    p = F.pkg("bash", "5.2-1")
    v1 = F.vuln("CVE-1", p, cvss_scores=[F.cvss(PWNKIT, 7.8)])
    v1.status = VulnStatus.FIXED
    v2 = F.vuln("CVE-2", p, cvss_scores=[F.cvss(PWNKIT, 7.8)])
    v2.status = VulnStatus.NOT_AFFECTED
    v3 = F.vuln("CVE-3", p, cvss_scores=[F.cvss(PWNKIT, 7.8)])
    threats = reverse_vulnerabilities(
        F.make_report(packages=[p], vulnerabilities=[v1, v2, v3]), ctx
    )
    assert [t.vulnerability for t in threats] == ["CVE-3"]


def test_hardening_lowers_score_and_lists_mitigations(ctx: ScanContext) -> None:
    p = F.pkg("nginx", "1.24-1")
    b = F.binary("/usr/sbin/nginx", package=p.id, used_by=["systemd:nginx"])
    hard = Hardening(user="www-data", no_new_privileges=True, protect_system="strict")
    svc = F.service(
        "nginx",
        executables=["/usr/sbin/nginx"],
        packages=[p.id],
        user="www-data",
        hardening=hard,
        listens=[F.tcp(443)],
    )
    v = F.vuln(
        "CVE-2024-7347",
        p,
        cvss_scores=[F.cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)],
        cwes=["CWE-787"],
        epss=0.2,
    )
    t = _one(F.make_report(packages=[p], services=[svc], binaries=[b], vulnerabilities=[v]), ctx)
    assert t.run_as == "www-data"
    assert t.postcondition == "local:www-data"
    assert any("NoNewPrivileges" in m for m in t.mitigations)
    assert t.score_factors["mitigation"] < 1.0


def test_on_demand_socket_activation(ctx: ScanContext) -> None:
    p = F.pkg("cups", "2.4-1")
    b = F.binary("/usr/sbin/cupsd", package=p.id, used_by=["systemd:cups"])
    svc = F.service(
        "cups",
        executables=["/usr/sbin/cupsd"],
        packages=[p.id],
        activation=[Activation.SOCKET],
        listens=[F.tcp(631, scope="loopback")],
    )
    v = F.vuln(
        "CVE-2024-00000",
        p,
        cvss_scores=[F.cvss(PWNKIT, 7.8)],
        cwes=["CWE-787"],
    )
    t = _one(F.make_report(packages=[p], services=[svc], binaries=[b], vulnerabilities=[v]), ctx)
    assert t.reachability is Reachability.ON_DEMAND_SERVICE
