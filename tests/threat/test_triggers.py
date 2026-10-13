"""Activation triggers and the trigger-aware postcondition / R5 logic.

Regression for a Kali host report: CVE-2024-35255 in a pip-installed
``azure-identity`` (CWE-362, "Elevation of Privilege" advisory, CVSS
C:H/I:N/A:N) produced local:unprivileged → root chains through rule R5
merely because *some* setuid binary existed on the system.
"""

from __future__ import annotations

import factory as F  # noqa: N812

from startup_sbom.context import ScanContext
from startup_sbom.models import (
    Activation,
    InitSystem,
    PackageType,
    Reachability,
    TriggerKind,
)
from startup_sbom.threat import build_attack_chains, reverse_vulnerabilities
from startup_sbom.threat.triggers import NO_TRIGGER

AZURE = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"
PRIVESC = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


def _azure_on_host_with_setuid() -> object:
    azure = F.pkg("azure-identity", "1.5.0", ptype=PackageType.PYPI)
    sudo_pkg = F.pkg("sudo", "1.9.16p2-1")
    libc = F.pkg("libc6", "2.41-6")
    sudo = F.binary(
        "/usr/bin/sudo",
        package=sudo_pkg.id,
        setuid=True,
        libraries=[F.lib("libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", libc.id)],
    )
    v = F.vuln(
        "CVE-2024-35255",
        azure,
        fixed=["1.16.1"],
        cvss_scores=[F.cvss(AZURE, 5.5)],
        cwes=["CWE-362"],
        summary="Azure Identity Libraries and Microsoft Authentication Library "
        "Elevation of Privilege Vulnerability",
    )
    return F.make_report(packages=[azure, sudo_pkg, libc], binaries=[sudo], vulnerabilities=[v])


def test_installed_confidentiality_only_flaw_is_not_root(ctx: ScanContext) -> None:
    rep = _azure_on_host_with_setuid()
    (t,) = reverse_vulnerabilities(rep, ctx)
    assert t.reachability is Reachability.INSTALLED
    assert t.postcondition == t.precondition
    assert t.triggers == []
    assert NO_TRIGGER in t.narrative
    assert "confidentiality-only" in t.narrative
    assert build_attack_chains(rep, [t], ctx) == []


def test_installed_privesc_flaw_without_privileged_loader_stays_put(ctx: ScanContext) -> None:
    """Even with an integrity impact, code nobody privileged runs gains nothing."""
    rep = _azure_on_host_with_setuid()
    rep.vulnerabilities[0].cvss = [F.cvss(PRIVESC, 7.8)]
    (t,) = reverse_vulnerabilities(rep, ctx)
    assert t.postcondition == t.precondition
    assert "installed only" in t.narrative
    assert build_attack_chains(rep, [t], ctx) == []


def test_impact_gate_can_be_disabled(ctx: ScanContext) -> None:
    ctx.options.cvss_impact_gate = False
    rep = _azure_on_host_with_setuid()
    (t,) = reverse_vulnerabilities(rep, ctx)
    assert "confidentiality-only" not in t.narrative
    # Still not root: nothing privileged loads the package.
    assert t.postcondition != "root"


def test_r5_requires_a_real_link_edge(ctx: ScanContext) -> None:
    """A library flaw reaches root only through a setuid binary that maps the library."""
    libfoo_pkg = F.pkg("libfoo1", "1.0-1")
    other = F.pkg("libbar1", "1.0-1")
    passwd_pkg = F.pkg("passwd", "1:4.13-1")
    passwd = F.binary(
        "/usr/bin/passwd",
        package=passwd_pkg.id,
        setuid=True,
        libraries=[F.lib("libfoo.so.1", "/usr/lib/libfoo.so.1", libfoo_pkg.id)],
    )
    vulns = [
        F.vuln("CVE-2099-0001", libfoo_pkg, cvss_scores=[F.cvss(PRIVESC, 7.8)], cwes=["CWE-787"]),
        F.vuln("CVE-2099-0002", other, cvss_scores=[F.cvss(PRIVESC, 7.8)], cwes=["CWE-787"]),
    ]
    rep = F.make_report(
        packages=[libfoo_pkg, other, passwd_pkg], binaries=[passwd], vulnerabilities=vulns
    )
    threats = {t.vulnerability: t for t in reverse_vulnerabilities(rep, ctx)}

    linked = threats["CVE-2099-0001"]
    assert linked.reachability is Reachability.SETUID
    assert linked.postcondition == "root"
    (trig,) = linked.triggers
    assert trig.kind is TriggerKind.SETUID
    assert trig.subject == "/usr/bin/passwd"
    assert trig.fired_by == "local user"
    assert trig.via == ["/usr/lib/libfoo.so.1"]

    unlinked = threats["CVE-2099-0002"]
    assert unlinked.reachability is Reachability.INSTALLED
    assert unlinked.postcondition != "root"

    chains = build_attack_chains(rep, list(threats.values()), ctx)
    rules = {s.rule for c in chains for s in c.steps}
    vulns_in_chains = {s.vulnerability for c in chains for s in c.steps if s.vulnerability}
    assert "R5" in rules
    assert vulns_in_chains == {"CVE-2099-0001"}


def test_loader_package_assumed_when_closure_missing(ctx: ScanContext) -> None:
    libc = F.pkg("libc6", "2.36-9")
    su_pkg = F.pkg("util-linux", "2.38-4")
    su = F.binary("/usr/bin/su", package=su_pkg.id, setuid=True)
    su.needed = ["libc.so.6"]  # dynamically linked, but no closure was recorded
    v = F.vuln("CVE-2023-4911", libc, cvss_scores=[F.cvss(PRIVESC, 7.8)], cwes=["CWE-787"])
    rep = F.make_report(packages=[libc, su_pkg], binaries=[su], vulnerabilities=[v])
    (t,) = reverse_vulnerabilities(rep, ctx)
    assert t.postcondition == "root"
    assert any(tr.kind is TriggerKind.SETUID and tr.subject == "/usr/bin/su" for tr in t.triggers)
    assert "assumed" in t.narrative


def test_non_root_service_privesc_cwe_stops_at_service_account(ctx: ScanContext) -> None:
    app = F.pkg("app", "1.0-1")
    svc = F.service(
        "app", executables=["/usr/bin/app"], packages=[app.id], user="app", enabled=True
    )
    v = F.vuln("CVE-2099-0003", app, cvss_scores=[F.cvss(PRIVESC, 7.8)], cwes=["CWE-269"])
    rep = F.make_report(packages=[app], services=[svc], vulnerabilities=[v])
    (t,) = reverse_vulnerabilities(rep, ctx)
    assert t.postcondition == "local:app"


def test_service_triggers_and_who_fires_them(ctx: ScanContext) -> None:
    web = F.pkg("web", "1.0-1")
    cronjob = F.pkg("backup", "1.0-1")
    svc_web = F.service(
        "web",
        executables=["/usr/sbin/web"],
        packages=[web.id],
        user="www-data",
        listens=[F.tcp(8080)],
    )
    svc_cron = F.service(
        "root:/etc/cron.d/backup:1",
        executables=["/usr/local/bin/backup"],
        packages=[cronjob.id],
        activation=[Activation.TIMER],
        init=InitSystem.CRON,
    )
    vulns = [
        F.vuln("CVE-2099-0004", web, cvss_scores=[F.cvss(PRIVESC, 7.8)]),
        F.vuln("CVE-2099-0005", cronjob, cvss_scores=[F.cvss(PRIVESC, 7.8)]),
    ]
    rep = F.make_report(
        packages=[web, cronjob], services=[svc_web, svc_cron], vulnerabilities=vulns
    )
    threats = {t.vulnerability: t for t in reverse_vulnerabilities(rep, ctx)}
    (web_trig,) = threats["CVE-2099-0004"].triggers
    assert (web_trig.kind, web_trig.fired_by, web_trig.runs_as) == (
        TriggerKind.BOOT,
        "network",
        "www-data",
    )
    assert "tcp/8080" in (web_trig.detail or "")
    (cron_trig,) = threats["CVE-2099-0005"].triggers
    assert (cron_trig.kind, cron_trig.fired_by, cron_trig.runs_as) == (
        TriggerKind.CRON,
        "system",
        "root",
    )
