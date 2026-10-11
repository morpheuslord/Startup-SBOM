"""SSVC decision-path traces reproduce the published tables, with correct flips."""

from __future__ import annotations

import itertools

import pytest

from startup_sbom.explain.ssvc_trace import (
    BOD,
    COORDINATOR,
    Point,
    decision_of,
    point_name,
    trace,
    trace_bod_26_04,
    trace_coordinator,
)
from startup_sbom.models import SSVCDecision
from startup_sbom.threat.ssvc import decide


def _points(values: tuple[str, ...]) -> list[Point]:
    return [Point(v, f"because {v}", [f"ev:{i}"]) for i, v in enumerate(values)]


def test_coordinator_trace_reproduces_every_table_row() -> None:
    for values, (row, outcome) in COORDINATOR.rows.items():
        tr = trace_coordinator(*_points(values))
        assert tr.row == row
        assert tr.outcome == outcome
        assert tr.tree == "cisa_coordinator_2_0_3"
        assert [n.value for n in tr.path] == list(values)
        assert [n.alternatives for n in tr.path] == [list(d) for d in COORDINATOR.domains]


def test_bod_trace_reproduces_every_table_row() -> None:
    for values, (row, outcome) in BOD.rows.items():
        tr = trace_bod_26_04(*_points(values))
        assert tr.row == row
        assert tr.outcome == outcome
        assert tr.tree == "cisa_bod_26_04_1_0_0"


def test_coordinator_agrees_with_the_threat_engine_table() -> None:
    """The verbatim CERT/CC CSV and threat.ssvc.decide() are the same function."""
    mission_to_exposure = {"low": "small", "medium": "controlled", "high": "open"}
    for values in COORDINATOR.rows:
        expl, auto, impact, mission = values
        tr = trace_coordinator(*_points(values))
        decision = decide(expl.replace(" ", "_"), auto, impact, mission_to_exposure[mission])
        assert decision_of(tr.outcome) is decision


def test_flips_are_exactly_the_single_input_changes_that_alter_the_outcome() -> None:
    for table, values in (
        (COORDINATOR, ("public poc", "no", "total", "medium")),
        (COORDINATOR, ("active", "yes", "total", "high")),
        (BOD, ("no", "yes", "no", "total")),
    ):
        tr = trace(table, _points(values))
        expected: list[str] = []
        base = table.rows[values][1]
        for k, domain in enumerate(table.domains):
            for alt in domain:
                if alt == values[k]:
                    continue
                v2 = list(values)
                v2[k] = alt
                outcome = table.rows[tuple(v2)][1]
                if outcome != base:
                    expected.append(f"{point_name(table.points[k])} = {alt} -> {outcome}")
        assert tr.flips == expected


def test_flip_count_is_consistent_across_the_whole_coordinator_table() -> None:
    for values in COORDINATOR.rows:
        tr = trace_coordinator(*_points(values))
        base = tr.outcome
        changed = sum(
            1
            for k, domain in enumerate(COORDINATOR.domains)
            for alt in domain
            if alt != values[k]
            and COORDINATOR.rows[(*tuple(values[:k]), alt, *tuple(values[k + 1 :]))][1] != base
        )
        assert len(tr.flips) == changed


def test_model_vocabulary_is_normalised_and_invalid_values_rejected() -> None:
    tr = trace_coordinator(
        Point("public_poc", "underscore vocabulary"),
        Point("no", "r"),
        Point("total", "r"),
        Point("medium", "r"),
    )
    assert tr.path[0].value == "public poc"
    with pytest.raises(ValueError, match="invalid value"):
        trace_coordinator(
            Point("rumoured", "?"), Point("no", "r"), Point("total", "r"), Point("medium", "r")
        )
    with pytest.raises(ValueError, match="decision points"):
        trace(COORDINATOR, _points(("none", "no", "partial")))


def test_trace_preserves_rationale_source_and_evidence() -> None:
    tr = trace_coordinator(
        Point("active", "listed in CISA KEV", ["ev:kev1"], "computed"),
        Point("no", "AC:H prevents automation", ["ev:cvss"], "computed"),
        Point("total", "C:H/I:H/A:H", ["ev:cvss"], "computed"),
        Point("medium", "not measurable from an image", [], "default"),
    )
    assert tr.path[0].evidence == ["ev:kev1"]
    assert tr.path[3].source == "default"
    assert tr.path[1].rationale == "AC:H prevents automation"
    assert decision_of(tr.outcome) in set(SSVCDecision)


def test_every_outcome_value_maps_to_a_decision() -> None:
    outcomes = {o for _, o in COORDINATOR.rows.values()}
    assert {decision_of(o) for o in outcomes} == set(SSVCDecision)
    # BOD outcomes are timelines, not decisions - they stay strings.
    assert {o for _, o in BOD.rows.values()} >= {"3 days", "14 days", "60 days"}


def test_tables_are_complete_cartesian_products() -> None:
    assert set(COORDINATOR.rows) == set(itertools.product(*COORDINATOR.domains))
    assert set(BOD.rows) == set(itertools.product(*BOD.domains))
    assert len(COORDINATOR.rows) == 36
    assert len(BOD.rows) == 16
