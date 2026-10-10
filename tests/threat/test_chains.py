"""Attack-chain construction and hardening-driven pruning."""

from __future__ import annotations

import factory as F  # noqa: N812

from startup_sbom.context import ScanContext
from startup_sbom.models import (
    BlastRadius,
    ContainerInfo,
    Hardening,
    SupplyChain,
)
from startup_sbom.threat import build_attack_chains, reverse_vulnerabilities
from startup_sbom.threat.facts import WritableUnitFact

NGINX_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
PWNKIT = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
XZ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def _nginx_pkexec(nnp: bool) -> object:
    nginx = F.pkg("nginx", "1.24-1")
    polkit = F.pkg("policykit-1", "0.105-31")
    nbin = F.binary("/usr/sbin/nginx", package=nginx.id, used_by=["systemd:nginx"])
    pkexec = F.binary("/usr/bin/pkexec", package=polkit.id, setuid=True, owner_uid=0)
    hard = Hardening(user="www-data", no_new_privileges=nnp)
    svc = F.service(
        "nginx",
        executables=["/usr/sbin/nginx"],
        packages=[nginx.id],
        user="www-data",
        hardening=hard,
        listens=[F.tcp(443)],
    )
    vn = F.vuln(
        "CVE-2024-RCE", nginx, cvss_scores=[F.cvss(NGINX_RCE, 9.8)], cwes=["CWE-94"], epss=0.5
    )
    vp = F.vuln(
        "CVE-2021-4034",
        polkit,
        cvss_scores=[F.cvss(PWNKIT, 7.8)],
        cwes=["CWE-787"],
        epss=0.94,
        kev=True,
    )
    return F.make_report(
        packages=[nginx, polkit],
        services=[svc],
        binaries=[nbin, pkexec],
        vulnerabilities=[vn, vp],
    )


def test_two_step_remote_to_root_chain(ctx: ScanContext) -> None:
    rep = _nginx_pkexec(nnp=False)
    threats = reverse_vulnerabilities(rep, ctx)
    chains = build_attack_chains(rep, threats, ctx)
    assert chains
    # A remote → www-data → root chain must be present (R1 then R4/R5).
    remote = [
        c for c in chains if c.entry == "remote" and any(s.to_state == "root" for s in c.steps)
    ]
    assert remote
    chain = remote[0]
    rules = [s.rule for s in chain.steps]
    assert "R1" in rules
    assert "R4" in rules or "R5" in rules
    states = [(s.from_state, s.to_state) for s in chain.steps]
    assert ("remote", "local:www-data") in states
    assert any(to == "root" for _, to in states)
    assert not chain.mitigated


def test_nonewprivileges_prunes_privesc_step(ctx: ScanContext) -> None:
    rep = _nginx_pkexec(nnp=True)
    threats = reverse_vulnerabilities(rep, ctx)
    chains = build_attack_chains(rep, threats, ctx)
    # The remote→root chain survives only in mitigated/downgraded form.
    remote_root = [c for c in chains if c.entry == "remote" and c.goal in ("root", "persistence")]
    assert remote_root
    for c in remote_root:
        privesc_steps = [s for s in c.steps if s.to_state == "root"]
        assert privesc_steps
        assert all(s.mitigated_by for s in privesc_steps)
        assert c.mitigated
    # And it ranks below its unmitigated counterpart.
    unmitigated = _nginx_pkexec(nnp=False)
    ch2 = build_attack_chains(unmitigated, reverse_vulnerabilities(unmitigated, ctx), ctx)
    assert ch2[0].score > remote_root[0].score


def test_privileged_container_escape(ctx: ScanContext) -> None:
    app = F.pkg("app", "1.0")
    abin = F.binary("/app/server", package=app.id, used_by=["container:entrypoint"])
    from startup_sbom.models import Activation, InitSystem

    svc = F.service(
        "entrypoint",
        executables=["/app/server"],
        packages=[app.id],
        init=InitSystem.CONTAINER,
        activation=[Activation.ENTRYPOINT],
    )
    v = F.vuln("CVE-APP", app, cvss_scores=[F.cvss(NGINX_RCE, 9.8)], cwes=["CWE-94"], epss=0.5)
    container = ContainerInfo(kind="container", privileged=True, exposed_ports=["8080/tcp"])
    rep = F.make_report(
        packages=[app], services=[svc], binaries=[abin], vulnerabilities=[v], container=container
    )
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert any(s.to_state == "container_escape" for c in chains for s in c.steps)
    assert any(s.rule == "R9" for c in chains for s in c.steps)


def test_docker_socket_mount_escape(ctx: ScanContext) -> None:
    from startup_sbom.models import Command

    app = F.pkg("ci-runner", "1.0")
    abin = F.binary("/usr/bin/runner", package=app.id, used_by=["systemd:runner"])
    svc = F.service("runner", executables=["/usr/bin/runner"], packages=[app.id], user="runner")
    svc.commands = [
        Command(directive="ExecStart", raw="/usr/bin/runner --sock /var/run/docker.sock")
    ]
    svc.evidence = ["mounts /var/run/docker.sock"]
    v = F.vuln("CVE-RUN", app, cvss_scores=[F.cvss(NGINX_RCE, 9.8)], cwes=["CWE-94"])
    rep = F.make_report(packages=[app], services=[svc], binaries=[abin], vulnerabilities=[v])
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert any(s.rule == "R9" for c in chains for s in c.steps)


def test_kernel_local_only_chain(ctx: ScanContext) -> None:
    kern = F.pkg("linux-image-6.1.0-amd64", "6.1.38-1")
    v = F.vuln(
        "CVE-2022-0847",
        kern,
        fixed=["6.1.38-2"],
        cvss_scores=[F.cvss(PWNKIT, 7.8)],
        cwes=["CWE-665"],
        kev=True,
    )
    rep = F.make_report(packages=[kern], vulnerabilities=[v])
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert chains
    local = [c for c in chains if c.entry == "local:unprivileged"]
    assert local
    assert any(s.to_state == "root" and s.rule == "R7" for c in local for s in c.steps)


def test_supply_chain_r10_preauth_root(ctx: ScanContext) -> None:
    pssh = F.pkg("openssh-server", "1:9.6p1-3")
    plz = F.pkg("liblzma5", "5.6.1-1")
    sshd = F.binary(
        "/usr/sbin/sshd",
        package=pssh.id,
        used_by=["systemd:ssh"],
        libraries=[F.lib("liblzma.so.5", "/usr/lib/liblzma.so.5", plz.id)],
    )
    liblz = F.binary("/usr/lib/liblzma.so.5", package=plz.id)
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[pssh.id], listens=[F.tcp(22)])
    v = F.vuln("CVE-2024-3094", plz, cvss_scores=[F.cvss(XZ, 10.0)], cwes=["CWE-506"], kev=True)
    sc = SupplyChain(
        blast_radius=[
            BlastRadius(package=plz.id, services=["systemd:ssh"], vulnerabilities=["CVE-2024-3094"])
        ]
    )
    rep = F.make_report(
        packages=[pssh, plz],
        services=[svc],
        binaries=[sshd, liblz],
        vulnerabilities=[v],
        supply_chain=sc,
    )
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert any(
        s.rule == "R10" and s.from_state == "remote" and s.to_state == "root"
        for c in chains
        for s in c.steps
    )


def test_extra_facts_writable_unit(ctx: ScanContext) -> None:
    p = F.pkg("app", "1.0")
    b = F.binary("/app/run", package=p.id, used_by=["systemd:app"])
    svc = F.service("app", executables=["/app/run"], packages=[p.id])
    v = F.vuln("CVE-X", p, cvss_scores=[F.cvss(PWNKIT, 7.8)], cwes=["CWE-787"])
    rep = F.make_report(packages=[p], services=[svc], binaries=[b], vulnerabilities=[v])
    extra = [WritableUnitFact(path="/etc/systemd/system/app.service", writable_by="deploy")]
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx, extra_facts=extra)
    assert any(s.rule == "R6" for c in chains for s in c.steps)


def test_max_chains_cap(ctx: ScanContext) -> None:
    rep = _nginx_pkexec(nnp=False)
    ctx.options.max_chains = 1
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert len(chains) <= 1


def test_chain_narrative_mentions_steps(ctx: ScanContext) -> None:
    rep = _nginx_pkexec(nnp=False)
    chains = build_attack_chains(rep, reverse_vulnerabilities(rep, ctx), ctx)
    assert "Step 1" in chains[0].narrative
    assert "Overall:" in chains[0].narrative
