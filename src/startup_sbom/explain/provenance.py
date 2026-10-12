"""Provenance store: content-addressed evidence and rule derivations ("why?" trees).

* ``Evidence.id = "ev:" + sha256(kind|source|locator|statement)[:12]`` — identical
  facts get identical ids across runs (reproducible output).
* ``Derivation`` records one rule firing; its confidence is the **weakest link** over
  its premises.  A conclusion supported by several derivations takes the best one.

NIST IR 8312 mapping: *Explanation* (every conclusion traces back to citable facts)
and *Knowledge limits* (assumptions are ``EvidenceKind.DEFAULT`` facts and confidence
degrades along the weakest link).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

from startup_sbom.models import Confidence, Derivation, Evidence, EvidenceKind

_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
_SEP = "\x1f"


def weakest(levels: Iterable[Confidence]) -> Confidence:
    """Lowest confidence (``HIGH`` for an empty input)."""
    return min(levels, key=_RANK.__getitem__, default=Confidence.HIGH)


def strongest(levels: Iterable[Confidence]) -> Confidence:
    """Highest confidence (``LOW`` for an empty input)."""
    return max(levels, key=_RANK.__getitem__, default=Confidence.LOW)


def evidence_id(kind: EvidenceKind, statement: str, source: str, locator: str | None) -> str:
    """Content-addressed evidence id."""
    blob = _SEP.join([kind.value, source, locator or "", statement])
    return "ev:" + hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def derivation_id(conclusion: str, rule: str, premises: Iterable[str]) -> str:
    """Content-addressed derivation id (premise order does not matter)."""
    blob = _SEP.join([conclusion, rule, *sorted(set(premises))])
    return "dv:" + hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()[:12]


@dataclass(slots=True)
class WhyNode:
    """One node of a "why?" tree."""

    id: str
    evidence: Evidence | None = None
    derivation: Derivation | None = None
    children: list[WhyNode] = field(default_factory=list)
    ref: bool = False  # already shown above (cycle / depth cut)


class Provenance:
    """Mutable evidence + derivation graph, seeded from (and written back to) a report."""

    def __init__(
        self,
        evidence: Iterable[Evidence] = (),
        derivations: Iterable[Derivation] = (),
    ) -> None:
        self.evidence: dict[str, Evidence] = {e.id: e for e in evidence}
        self.derivations: dict[str, Derivation] = {}
        self.by_conclusion: dict[str, list[str]] = {}
        for d in derivations:
            self._store(d)

    def _store(self, d: Derivation) -> None:
        if d.id in self.derivations:
            return
        self.derivations[d.id] = d
        self.by_conclusion.setdefault(d.conclusion, []).append(d.id)

    def fact(
        self,
        kind: EvidenceKind,
        statement: str,
        source: str,
        *,
        locator: str | None = None,
        digest: str | None = None,
        retrieved: str | None = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> str:
        """Record an atomic fact; returns its (stable) id."""
        eid = evidence_id(kind, statement, source, locator)
        if eid not in self.evidence:
            self.evidence[eid] = Evidence(
                id=eid,
                kind=kind,
                statement=statement,
                source=source,
                locator=locator,
                digest=digest,
                retrieved=retrieved,
                confidence=confidence,
            )
        return eid

    def derive(self, conclusion: str, rule: str, premises: Iterable[str]) -> str:
        """Record a rule firing; confidence is the weakest link over ``premises``."""
        prem = sorted(set(premises))
        did = derivation_id(conclusion, rule, prem)
        if did not in self.derivations:
            conf = weakest(self.confidence(p) for p in prem)
            self._store(
                Derivation(id=did, conclusion=conclusion, rule=rule, premises=prem, confidence=conf)
            )
        return did

    def confidence(self, node: str) -> Confidence:
        """Confidence of an evidence id, derivation id or conclusion."""
        if node in self.evidence:
            return self.evidence[node].confidence
        if node in self.derivations:
            return self.derivations[node].confidence
        return strongest(self.derivations[d].confidence for d in self.by_conclusion.get(node, []))

    def why(self, node: str, depth: int = 6) -> WhyNode:
        """Proof tree for ``node`` (cycle-safe, depth-bounded)."""
        seen: set[str] = set()

        def build(n: str, d: int) -> WhyNode:
            if n in self.evidence:
                return WhyNode(id=n, evidence=self.evidence[n])
            if n in seen or d <= 0:
                return WhyNode(id=n, ref=True)
            seen.add(n)
            if n in self.derivations:
                dv = self.derivations[n]
                return WhyNode(id=n, derivation=dv, children=[build(p, d - 1) for p in dv.premises])
            return WhyNode(id=n, children=[build(x, d - 1) for x in self.by_conclusion.get(n, [])])

        return build(node, depth)

    def sorted_evidence(self) -> list[Evidence]:
        return [self.evidence[k] for k in sorted(self.evidence)]

    def sorted_derivations(self) -> list[Derivation]:
        return [self.derivations[k] for k in sorted(self.derivations)]
