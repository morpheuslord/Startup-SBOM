"""Data loaders, ATT&CK/CWE lookups, SSVC table and determinism."""

from __future__ import annotations

import factory as F  # noqa: N812

from startup_sbom.context import ScanContext
from startup_sbom.models import Consequence, CVSSScore, SSVCDecision
from startup_sbom.threat import (
    attack,
    build_attack_chains,
    cwe,
    reverse_vulnerabilities,
    ssvc,
    technique,
)
from startup_sbom.threat.cvss import parse

PWNKIT = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


# --------------------------------------------------------------------------- ATT&CK
def test_technique_lookup() -> None:
    t = technique("T1068")
    assert t is not None
    assert t.id == "T1068"
    assert "Privilege Escalation" in (t.tactic or "")
    assert technique("T9999") is None


def test_technique_prefers_tactic() -> None:
    # T1543.002 (Systemd Service) spans persistence and privilege-escalation.
    pe = technique("T1543.002", ("privilege-escalation",))
    assert pe is not None
    assert pe.tactic == "Privilege Escalation"


def test_kev_cve_mapping_pwnkit() -> None:
    m = attack.cve_mapping(["CVE-2021-4034"])
    assert m is not None
    assert "T1068" in m.exploitation
    assert m.sources
    assert "KEV" in m.sources[0]


def test_cwe_mapping_fallback() -> None:
    # OS command injection → T1059.004 via the CTID methodology table.
    m = attack.cwe_mapping([78])
    assert "T1059.004" in m.primary


# --------------------------------------------------------------------------- CWE
def test_cwe_consequences_memory_write_rce() -> None:
    facts = parse(CVSSScore(version="3.1", vector=PWNKIT))
    cons, ev = cwe.consequences(["CWE-787"], facts)
    assert Consequence.RCE in cons
    assert ev
    assert "CWE-787" in ev[0]


def test_cwe_category_resolves_via_members() -> None:
    # CWE-264 is an obsolete category: it still yields a privilege consequence.
    facts = parse(CVSSScore(version="3.1", vector=PWNKIT))
    cons, _ = cwe.consequences(["CWE-264"], facts)
    assert Consequence.PRIVESC in cons or Consequence.AUTH_BYPASS in cons


def test_cwe_supply_chain() -> None:
    facts = parse(CVSSScore(version="3.1", vector=PWNKIT))
    cons, _ = cwe.consequences(["CWE-506"], facts)
    assert Consequence.SUPPLY_CHAIN in cons


def test_memory_read_is_disclosure_not_rce() -> None:
    # Out-of-bounds read, confidentiality-only impact ⇒ no code execution.
    facts = parse(CVSSScore(version="3.1", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
    cons, _ = cwe.consequences(["CWE-125"], facts)
    assert Consequence.RCE not in cons
    assert Consequence.INFO_DISCLOSURE in cons


# --------------------------------------------------------------------------- CVSS
def test_cvss_v4_parsing() -> None:
    f = parse(
        CVSSScore(
            version="4.0", vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
    )
    assert f.attack_vector == "network"
    assert f.privileges_required == "none"
    assert f.automatable


def test_cvss_malformed_is_unknown() -> None:
    f = parse(CVSSScore(version="3.1", vector="not a vector"))
    assert not f.known
    assert f.attack_vector == "unknown"


# --------------------------------------------------------------------------- SSVC
def test_ssvc_table_matches_cisa_rows() -> None:
    # active/yes/total → Act regardless of exposure proxy.
    assert ssvc.decide("active", "yes", "total", "open") is SSVCDecision.ACT
    assert ssvc.decide("none", "no", "partial", "small") is SSVCDecision.TRACK
    # public_poc/no/total with controlled (→medium) exposure → Track*.
    assert ssvc.decide("public_poc", "no", "total", "controlled") is SSVCDecision.TRACK_STAR


# --------------------------------------------------------------------------- determinism
def _sample_report() -> object:
    pssh = F.pkg("openssh-server", "1:9.6p1-3")
    polkit = F.pkg("policykit-1", "0.105-31")
    sshd = F.binary("/usr/sbin/sshd", package=pssh.id, used_by=["systemd:ssh"])
    pkexec = F.binary("/usr/bin/pkexec", package=polkit.id, setuid=True, owner_uid=0)
    svc = F.service("ssh", executables=["/usr/sbin/sshd"], packages=[pssh.id], listens=[F.tcp(22)])
    v1 = F.vuln(
        "CVE-2024-6387",
        pssh,
        fixed=["1:9.6p1-5"],
        cvss_scores=[F.cvss("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1)],
        cwes=["CWE-364"],
        epss=0.9,
    )
    v2 = F.vuln(
        "CVE-2021-4034",
        polkit,
        cvss_scores=[F.cvss(PWNKIT, 7.8)],
        cwes=["CWE-787"],
        epss=0.94,
        kev=True,
    )
    return F.make_report(
        packages=[pssh, polkit], services=[svc], binaries=[sshd, pkexec], vulnerabilities=[v1, v2]
    )


def test_deterministic_threats(ctx: ScanContext) -> None:
    a = reverse_vulnerabilities(_sample_report(), ctx)  # type: ignore[arg-type]
    b = reverse_vulnerabilities(_sample_report(), ctx)  # type: ignore[arg-type]
    assert [t.model_dump() for t in a] == [t.model_dump() for t in b]
    assert [t.id for t in a] == sorted({t.id for t in a}, key=[t.id for t in a].index)


def test_deterministic_chains(ctx: ScanContext) -> None:
    rep = _sample_report()
    ta = reverse_vulnerabilities(rep, ctx)  # type: ignore[arg-type]
    ca = build_attack_chains(rep, ta, ctx)  # type: ignore[arg-type]
    cb = build_attack_chains(rep, ta, ctx)  # type: ignore[arg-type]
    assert [c.model_dump() for c in ca] == [c.model_dump() for c in cb]
    assert [c.id for c in ca] == [
        c.id for c in sorted(ca, key=lambda c: (c.mitigated, -c.score, c.id))
    ]


def test_stable_ids_across_processes(ctx: ScanContext) -> None:
    # IDs are content hashes, so they are reproducible, not object-identity based.
    a = reverse_vulnerabilities(_sample_report(), ctx)  # type: ignore[arg-type]
    ids = {t.vulnerability: t.id for t in a}
    assert ids["CVE-2021-4034"].startswith("threat-")
    b = reverse_vulnerabilities(_sample_report(), ctx)  # type: ignore[arg-type]
    assert {t.vulnerability: t.id for t in b} == ids
