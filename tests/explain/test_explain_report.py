"""End-to-end behaviour of explain_report on the regreSSHion + pkexec worked example."""

from __future__ import annotations

import math
from itertools import combinations

import explaindata
import pytest

from startup_sbom.context import ScanContext
from startup_sbom.explain import explain_report, intel_summary
from startup_sbom.models import Report


@pytest.fixture
def rep(ctx: ScanContext) -> Report:
    report = explaindata.regresshion_pkexec(ctx)
    explain_report(report)
    return report


def test_threat_fields_are_filled_and_exact(rep: Report) -> None:
    assert rep.threats
    for t in rep.threats:
        e = t.explanation
        assert e is not None
        assert e.subject == t.id
        assert e.method.value == "sequential+lmdi"
        total = e.baseline + math.fsum(f.contribution for f in e.factors)
        assert math.isclose(total, e.total, abs_tol=1e-6)
        assert math.isclose(t.risk_score, round(min(100.0, max(0.0, e.total)), 1), abs_tol=1e-9)
        assert t.score_factors == {f.name: round(f.contribution, 3) for f in e.factors}
        assert t.evidence == sorted(t.evidence)
        assert t.evidence, "threats must cite evidence/derivation ids"
        assert t.ssvc is not None
        assert t.ssvc.trace is not None
        assert t.ssvc.bod_26_04 is not None
        assert t.ssvc.trace.outcome.lower() == t.ssvc.decision.value.lower()


def test_chains_have_ids_derivations_and_exact_explanations(rep: Report) -> None:
    assert rep.attack_chains
    for c in rep.attack_chains:
        assert c.explanation is not None
        total = c.explanation.baseline + math.fsum(f.contribution for f in c.explanation.factors)
        assert math.isclose(total, c.explanation.total, abs_tol=1e-6)
        for s in c.steps:
            assert s.id is not None
            assert s.id.startswith("step:")
            assert s.derivation is not None
            assert s.derivation.startswith("dv:")


def test_report_provenance_is_sorted_and_resolvable(rep: Report) -> None:
    ev_ids = [e.id for e in rep.evidence]
    dv_ids = [d.id for d in rep.derivations]
    assert ev_ids == sorted(ev_ids)
    assert len(set(ev_ids)) == len(ev_ids)
    assert dv_ids == sorted(dv_ids)
    assert len(set(dv_ids)) == len(dv_ids)
    known = set(ev_ids) | set(dv_ids)
    for d in rep.derivations:
        assert set(d.premises) <= known
    for t in rep.threats:
        assert set(t.evidence) <= known


def test_drivers_sum_to_system_risk(rep: Report) -> None:
    assert rep.explanations is not None
    assert rep.explanations.system is not None
    g = rep.explanations.system
    for kind in ("package", "vendor", "service"):
        total = math.fsum(d.contribution for d in g.drivers if d.kind == kind)
        assert math.isclose(total, g.system_risk, abs_tol=1e-6), kind
    items = math.fsum(d.contribution for d in g.drivers if d.kind in ("chain", "threat"))
    assert math.isclose(items, g.system_risk, abs_tol=1e-6)
    assert g.pareto_80


def test_fix_plan_breaks_all_chains_and_is_minimal(rep: Report) -> None:
    ex = rep.explanations
    assert ex is not None
    assert ex.fixes
    fixes = {f.id: f for f in ex.fixes}
    all_breaks = {s for f in ex.fixes for s in f.breaks}
    breakable = {c.id for c in rep.attack_chains if any(s.id in all_breaks for s in c.steps)}
    assert breakable == {c.id for c in rep.attack_chains}, "every chain has a candidate fix"

    def broken_by(ids: tuple[str, ...]) -> set[str]:
        steps = {s for i in ids for s in fixes[i].breaks}
        return {c.id for c in rep.attack_chains if any(st.id in steps for st in c.steps)}

    exact = [w for w in ex.fix_plan if w.method == "exact_hitting_set"]
    assert exact
    for plan in exact:
        assert set(plan.chains_broken) == breakable
        assert broken_by(tuple(plan.fixes)) == breakable
        for k in range(1, len(plan.fixes)):  # minimal: no proper subset suffices
            for subset in combinations(plan.fixes, k):
                assert broken_by(subset) != breakable
        assert plan.risk_after < plan.risk_before
    # the worked example needs both upgrades: sshd -> root and pkexec -> root are disjoint
    kinds = {fixes[i].target for i in exact[0].fixes}
    assert len(exact[0].fixes) == 2
    assert any("openssh" in t for t in kinds)
    assert any("policykit" in t for t in kinds)


def test_what_if_is_per_single_fix_and_consistent(rep: Report) -> None:
    ex = rep.explanations
    assert ex is not None
    assert {tuple(w.fixes) for w in ex.what_if} == {(f.id,) for f in ex.fixes}
    for w in ex.what_if:
        assert w.method == "single"
        assert w.risk_after <= w.risk_before + 1e-9


def test_idempotent_and_deterministic(ctx: ScanContext) -> None:
    a = explaindata.regresshion_pkexec(ctx)
    explain_report(a)
    first = a.model_dump_json()
    explain_report(a)
    assert a.model_dump_json() == first, "explain_report must be idempotent"
    b = explaindata.regresshion_pkexec(ctx)
    explain_report(b)
    assert b.model_dump_json() == first, "explain_report must be deterministic"


def test_never_raises_on_empty_or_partial_reports(ctx: ScanContext) -> None:
    import factory as F  # noqa: N812

    empty = F.make_report()
    explain_report(empty)
    assert empty.explanations is not None or empty.explanations is None  # no exception
    partial = explaindata.regresshion_pkexec(ctx)
    partial.vulnerabilities = []  # threats without their vulnerability records
    partial.services = []
    explain_report(partial)
    assert partial.threats  # still explained from the recorded fields
    for t in partial.threats:
        assert t.explanation is not None


def test_intel_raises_ssvc_exploitation_and_adds_maturity_factor(ctx: ScanContext) -> None:
    rep = explaindata.regresshion_pkexec(ctx)
    rep.intel = [explaindata.sshd_intel()]
    explain_report(rep)
    t = next(t for t in rep.threats if t.vulnerability == "CVE-2024-6387")
    assert t.ssvc is not None
    assert t.ssvc.exploitation == "active"  # raised from public_poc (EPSS) by intel
    assert t.ssvc.trace is not None
    assert "exploit intelligence" in t.ssvc.trace.path[0].rationale
    assert t.explanation is not None
    by = {f.name: f for f in t.explanation.factors}
    assert "exploit_maturity" in by
    assert by["exploit_maturity"].value == "weaponized"
    assert t.intel_summary is not None
    assert "Metasploit module" in t.intel_summary
    assert "2 Exploit-DB entries" in t.intel_summary
    assert "88 PoC repos (unverified)" in t.intel_summary


def test_intel_never_lowers_exploitation(ctx: ScanContext) -> None:
    rep = explaindata.regresshion_pkexec(ctx, kev_sshd=True)
    rep.intel = [explaindata.sshd_intel(exploitation="none", maturity="none")]
    explain_report(rep)
    t = next(t for t in rep.threats if t.vulnerability == "CVE-2024-6387")
    assert t.ssvc is not None
    assert t.ssvc.exploitation == "active"  # KEV evidence outranks a quiet intel bundle


def test_intel_summary_wording() -> None:
    assert intel_summary(explaindata.sshd_intel()) == (
        "Metasploit module, 2 Exploit-DB entries, 88 PoC repos (unverified)"
    )
    bundle = explaindata.sshd_intel()
    assert intel_summary(bundle, kev=True).endswith(", KEV")
