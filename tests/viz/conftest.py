"""Fixtures for the visualisation tests: a fully explained report with hostile strings."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "threat"))
sys.path.insert(0, str(Path(__file__).parent.parent / "explain"))

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.explain import explain_report
from startup_sbom.models import BlastRadius, Report
from startup_sbom.rootfs import DirectoryRootFS

#: Terminal-escape, markup, bidi and zero-width payloads that must never reach output raw.
EVIL = "x\x1b]0;pwned\x07\x1b[2Jy[bold red]M[/]\u202eZ\u200b</script><script>alert(1)</script>"


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    root = tmp_path / "root"
    root.mkdir()
    return ScanContext(fs=DirectoryRootFS(root), options=ScanOptions(offline=True))


@pytest.fixture
def hostile_report(ctx: ScanContext) -> Report:
    """The regreSSHion + pkexec example with hostile text in every injectable field."""
    import explaindata

    report = explaindata.regresshion_pkexec(ctx)
    report.intel = [explaindata.sshd_intel()]
    for v in report.vulnerabilities:
        v.summary = EVIL
    explain_report(report)
    for t in report.threats:
        t.title = EVIL + t.title
        t.narrative = EVIL + t.narrative
        if t.ssvc is not None and t.ssvc.trace is not None:
            for node in t.ssvc.trace.path:
                node.rationale = EVIL + node.rationale
    for c in report.attack_chains:
        c.narrative = EVIL + c.narrative
        for s in c.steps:
            s.title = EVIL + s.title
    for e in report.evidence:
        e.statement = EVIL + e.statement
    report.supply_chain.blast_radius = [
        BlastRadius(
            package=report.packages[0].id,
            vendor=EVIL,
            services=[report.services[0].id],
            binaries=["/usr/sbin/sshd"],
            example_paths=[["/usr/sbin/sshd", report.services[0].id], [EVIL, "/usr/bin/pkexec"]],
            vulnerabilities=["CVE-2024-6387"],
            score=74.0,
        )
    ]
    return report
