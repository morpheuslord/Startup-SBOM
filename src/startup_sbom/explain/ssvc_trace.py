"""SSVC decision-path explanations over the published CERT/CC tables.

The two tables below are reproduced verbatim from the CERT/CC SSVC project
(<https://github.com/CERTCC/SSVC>, ``data/csv/cisa/``, Apache License 2.0):
``cisa_coordinator_2_0_3.csv`` (CISA Coordinator tree) and
``cisa_bod_26_04_1_0_0.csv`` (BOD 26-04 remediation timelines).

A :class:`SSVCTrace` records the chosen value of every decision point with its
alternatives, rationale, evidence ids and source, the table row used and every
single-input change that would flip the outcome (an exact local counterfactual).

NIST IR 8312 mapping: *Explanation accuracy* — the trace reads the very table row
that produced the decision; *Knowledge limits* — inputs that are proxies or defaults
are labelled by ``DecisionNode.source`` and their rationale.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from startup_sbom.models import DecisionNode, SSVCDecision, SSVCTrace

COORDINATOR_TREE = "cisa_coordinator_2_0_3"
BOD_TREE = "cisa_bod_26_04_1_0_0"

COORDINATOR_CSV = """\
row,Exploitation v1.1.0,Automatable v2.0.0,Technical Impact v1.0.0,Mission and Well-Being Impact v1.0.0,CISA Levels v1.1.0 (cisa)
0,none,no,partial,low,track
1,none,no,partial,medium,track
2,none,no,partial,high,track
3,none,no,total,low,track
4,none,no,total,medium,track
5,none,no,total,high,track*
6,none,yes,partial,low,track
7,none,yes,partial,medium,track
8,none,yes,partial,high,attend
9,none,yes,total,low,track
10,none,yes,total,medium,track
11,none,yes,total,high,attend
12,public poc,no,partial,low,track
13,public poc,no,partial,medium,track
14,public poc,no,partial,high,track*
15,public poc,no,total,low,track
16,public poc,no,total,medium,track*
17,public poc,no,total,high,attend
18,public poc,yes,partial,low,track
19,public poc,yes,partial,medium,track
20,public poc,yes,partial,high,attend
21,public poc,yes,total,low,track
22,public poc,yes,total,medium,track*
23,public poc,yes,total,high,attend
24,active,no,partial,low,track
25,active,no,partial,medium,track
26,active,no,partial,high,attend
27,active,no,total,low,track
28,active,no,total,medium,attend
29,active,no,total,high,act
30,active,yes,partial,low,attend
31,active,yes,partial,medium,attend
32,active,yes,partial,high,act
33,active,yes,total,low,attend
34,active,yes,total,medium,act
35,active,yes,total,high,act
"""  # noqa: E501

BOD_CSV = """\
row,In KEV v1.0.0 (cisa),Publicly Exposed v1.0.0 (cisa),Automatable v2.0.0,Technical Impact v1.0.0,CISA BOD 26-04 Remediation Timelines v1.0.0 (cisa)
0,no,no,no,partial,fix on system upgrade
1,yes,no,no,partial,14 days
2,no,yes,no,partial,60 days
3,no,no,yes,partial,60 days
4,no,no,no,total,fix on system upgrade
5,yes,yes,no,partial,14 days
6,yes,no,yes,partial,14 days
7,no,yes,yes,partial,14 days
8,yes,no,no,total,14 days
9,no,yes,no,total,14 days
10,no,no,yes,total,60 days
11,yes,yes,yes,partial,3 days
12,yes,yes,no,total,3 days & forensic investigation
13,yes,no,yes,total,3 days & forensic investigation
14,no,yes,yes,total,3 days
15,yes,yes,yes,total,3 days & forensic investigation
"""  # noqa: E501

Source = Literal["cisa_adp", "computed", "user", "default"]


@dataclass(frozen=True, slots=True)
class Table:
    """A parsed CERT/CC decision table."""

    name: str
    points: tuple[str, ...]  # decision-point headers, e.g. "Exploitation v1.1.0"
    domains: tuple[tuple[str, ...], ...]  # values per point in table order
    rows: dict[tuple[str, ...], tuple[int, str]]  # values -> (row, outcome)

    def lookup(self, values: Sequence[str]) -> tuple[int, str]:
        return self.rows[tuple(values)]


def _load(name: str, text: str) -> Table:
    data = list(csv.reader(io.StringIO(text)))
    header, body = data[0], [r for r in data[1:] if r]
    points = tuple(header[1:-1])
    domains: list[list[str]] = [[] for _ in points]
    rows: dict[tuple[str, ...], tuple[int, str]] = {}
    for r in body:
        vals = tuple(r[1:-1])
        for k, v in enumerate(vals):
            if v not in domains[k]:
                domains[k].append(v)
        rows[vals] = (int(r[0]), r[-1])
    return Table(name, points, tuple(tuple(d) for d in domains), rows)


COORDINATOR = _load(COORDINATOR_TREE, COORDINATOR_CSV)
BOD = _load(BOD_TREE, BOD_CSV)

_DECISION = {
    "track": SSVCDecision.TRACK,
    "track*": SSVCDecision.TRACK_STAR,
    "attend": SSVCDecision.ATTEND,
    "act": SSVCDecision.ACT,
}


def decision_of(outcome: str) -> SSVCDecision:
    """Map a coordinator-table outcome to :class:`SSVCDecision`."""
    return _DECISION[outcome.lower()]


def table_value(value: str) -> str:
    """Model vocabulary -> table vocabulary (``public_poc`` -> ``public poc``)."""
    return value.replace("_", " ")


def point_name(header: str) -> str:
    """``"Exploitation v1.1.0"`` -> ``"Exploitation"``."""
    name = header.removesuffix(" (cisa)")
    head, _, tail = name.rpartition(" v")
    return head if head and tail[:1].isdigit() else name


@dataclass(slots=True)
class Point:
    """The chosen value of one decision point plus its justification."""

    value: str
    rationale: str
    evidence: list[str] = field(default_factory=list)
    source: Source = "computed"


def flips(table: Table, values: Sequence[str]) -> list[str]:
    """Every single-input change that alters the outcome, in table order."""
    base = table.lookup(values)[1]
    out: list[str] = []
    for k, dom in enumerate(table.domains):
        for alt in dom:
            if alt == values[k]:
                continue
            v2 = list(values)
            v2[k] = alt
            outcome = table.lookup(v2)[1]
            if outcome != base:
                out.append(f"{point_name(table.points[k])} = {alt} -> {outcome}")
    return out


def trace(table: Table, points: Sequence[Point]) -> SSVCTrace:
    """Trace a decision through ``table`` (values are normalised to table vocabulary)."""
    if len(points) != len(table.points):
        raise ValueError(f"{table.name} needs {len(table.points)} decision points")
    values = [table_value(p.value) for p in points]
    for k, v in enumerate(values):
        if v not in table.domains[k]:
            raise ValueError(f"{point_name(table.points[k])}: invalid value {v!r}")
    row, outcome = table.lookup(values)
    path = [
        DecisionNode(
            decision_point=table.points[k],
            value=values[k],
            alternatives=list(table.domains[k]),
            rationale=p.rationale,
            evidence=sorted(set(p.evidence)),
            source=p.source,
        )
        for k, p in enumerate(points)
    ]
    return SSVCTrace(
        tree=table.name, path=path, row=row, outcome=outcome, flips=flips(table, values)
    )


def trace_coordinator(
    exploitation: Point, automatable: Point, technical_impact: Point, mission: Point
) -> SSVCTrace:
    """CISA Coordinator v2.0.3 decision path."""
    return trace(COORDINATOR, [exploitation, automatable, technical_impact, mission])


def trace_bod_26_04(
    in_kev: Point, publicly_exposed: Point, automatable: Point, technical_impact: Point
) -> SSVCTrace:
    """BOD 26-04 remediation-timeline decision path."""
    return trace(BOD, [in_kev, publicly_exposed, automatable, technical_impact])
