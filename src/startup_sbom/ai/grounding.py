"""Grounding: machine-check every AI output against the report it claims to describe.

Checks (on pydantic outputs and on raw JSON from plugin/remote agents alike):

* every cited id (evidence refs, ``cites``, ``threat_id``, ``chain_id``, ``fixes``,
  ``affected_services``) exists in the report;
* every CVE/GHSA/CWE/ATT&CK id mentioned in any string is present in the report;
* every numeric claim (``numbers``: risk score, EPSS, likelihood, CVSS ...) matches
  the report within tolerance, plus a text heuristic for "EPSS 0.43" / "risk 92.5";
* claims and explained items cite at least one id.

:func:`attach_grounding` wires the check as a pydantic-ai output validator that raises
``ModelRetry`` with precise feedback and, on the last attempt, accepts the output so the
issues are flagged in the :class:`~startup_sbom.models.GroundingResult` instead.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel

from startup_sbom.ai.index import (
    ATTACK_RE,
    CVE_RE,
    CWE_RE,
    GHSA_RE,
    ID_KINDS,
    ReportIndex,
)
from startup_sbom.models import GroundingIssue, GroundingResult
from startup_sbom.textsafe import clean

if TYPE_CHECKING:
    from pydantic_ai import Agent

IssueCode = Literal["unknown_id", "uncited", "numeric_mismatch", "unknown_number_ref"]

_TOLERANCE = {
    "risk_score": 0.5,
    "risk": 0.5,
    "score": 0.5,
    "blast_score": 0.5,
    "blast_radius": 0.5,
    "epss": 0.01,
    "epss_percentile": 0.01,
    "percentile": 0.01,
    "likelihood": 0.01,
    "impact": 0.01,
    "cvss": 0.05,
    "cvss_score": 0.05,
    "base_score": 0.05,
    "exposure": 0.05,
}
_ID_FIELDS = {
    "threat_id": "threat",
    "chain_id": "chain",
    "fixes": "threat",
    "affected_services": "service",
}
_SKIP_SCAN = {"ref", "cites", "kind", "threat_id", "chain_id", "fixes", "affected_services"}
_SENTENCE = re.compile(r"(?<=[.!?;\n])\s+")
_EPSS_TEXT = re.compile(r"\bEPSS\b[^0-9%]{0,24}(\d+(?:\.\d+)?)\s*(%)?", re.IGNORECASE)
_RISK_TEXT = re.compile(r"\brisk(?:[ _-]?score)?\b[^0-9]{0,12}(\d+(?:\.\d+)?)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Issue:
    """One grounding problem at a JSON path of the checked output."""

    path: str
    code: IssueCode
    detail: str

    def render(self) -> str:
        return f"{self.path}: {self.detail}"


def _within(field: str, claimed: float, actual: float) -> bool:
    tol = _TOLERANCE.get(field.rsplit(".", maxsplit=1)[-1], 0.01 * max(1.0, abs(actual)))
    if math.isclose(claimed, actual, abs_tol=tol):
        return True
    # a probability stated as a percentage ("43" for 0.43)
    if not (0.0 <= actual <= 1.0 and claimed > 1.0):
        return False
    return math.isclose(claimed / 100, actual, abs_tol=tol)


class _Checker:
    def __init__(self, index: ReportIndex, *, require_citations: bool) -> None:
        self.index = index
        self.require_citations = require_citations
        self.issues: list[Issue] = []
        self.threat_ids = sorted(index.threats, key=len, reverse=True)[:2000]

    def add(self, path: str, code: IssueCode, detail: str) -> None:
        self.issues.append(Issue(path, code, clean(detail, max_len=300)))

    # -- ids --------------------------------------------------------------
    def check_ref(
        self, path: str, ref: Any, kind: str | None = None, *, strict: bool = False
    ) -> None:
        if not isinstance(ref, str) or not ref.strip():
            self.add(path, "unknown_id", "empty or non-string id")
            return
        if kind is not None and kind in ID_KINDS and self.index.resolve(kind, ref):
            return
        if strict and kind is not None:
            self.add(path, "unknown_id", f"{kind} id {ref!r} is not in the report")
            return
        if not self.index.known(ref):
            self.add(path, "unknown_id", f"id {ref!r} is not in the report")

    def check_number(self, path: str, item: Any) -> None:
        if not isinstance(item, Mapping):
            return
        ref, field, value = item.get("ref"), item.get("field"), item.get("value")
        if not isinstance(ref, str) or not isinstance(field, str):
            self.add(path, "unknown_number_ref", "numeric claim without ref/field")
            return
        known, actual = self.index.numeric(ref, field)
        if not known:
            self.add(path, "unknown_number_ref", f"number cites unknown id {ref!r}")
            return
        if actual is None:
            self.add(path, "unknown_number_ref", f"{ref!r} has no numeric field {field!r}")
            return
        if not isinstance(value, int | float) or isinstance(value, bool):
            self.add(path, "numeric_mismatch", f"{field} of {ref!r} is not a number: {value!r}")
            return
        claimed = float(value)
        if not _within(field.lower(), claimed, actual):
            self.add(
                path,
                "numeric_mismatch",
                f"{field} of {ref!r} is {actual:g} in the report, not {claimed:g}",
            )

    # -- free text ----------------------------------------------------------
    def scan_text(self, path: str, text: str) -> None:
        idx = self.index
        for rx, known, label in (
            (CVE_RE, idx.cves, "CVE"),
            (GHSA_RE, idx.cves, "GHSA"),
            (CWE_RE, idx.cwes, "CWE"),
        ):
            for match in dict.fromkeys(m.upper() for m in rx.findall(text)):
                if match not in known:
                    self.add(
                        path, "unknown_id", f"mentions {label} {match} which is not in the report"
                    )
        for tech in dict.fromkeys(ATTACK_RE.findall(text)):
            if tech not in idx.techniques:
                self.add(path, "unknown_id", f"mentions ATT&CK {tech} which is not in the report")
        self._text_numbers(path, text)

    def _text_numbers(self, path: str, text: str) -> None:
        for sentence in _SENTENCE.split(text):
            cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(sentence)))
            tids = [t for t in self.threat_ids if t in sentence]
            # Mask ids first so their digits ("TH-0001", "CVE-2024-6387") are never
            # mistaken for a stated risk score or EPSS value.
            masked = CVE_RE.sub("<CVE>", sentence)
            for tid in tids:
                masked = masked.replace(tid, "<THREAT>")
            if len(cves) == 1 and cves[0] in self.index.cves:
                for m in _EPSS_TEXT.finditer(masked):
                    claimed = float(m.group(1)) / (100 if m.group(2) else 1)
                    _, actual = self.index.numeric(cves[0], "epss")
                    if actual is not None and not _within("epss", claimed, actual):
                        self.add(
                            path,
                            "numeric_mismatch",
                            f"text states EPSS {m.group(0).strip()!r} for {cves[0]}, "
                            f"report has {actual:g}",
                        )
            if len(tids) == 1:
                actual_risk = self.index.threats[tids[0]].risk_score
                for m in _RISK_TEXT.finditer(masked):
                    claimed = float(m.group(1))
                    if not _within("risk_score", claimed, actual_risk):
                        self.add(
                            path,
                            "numeric_mismatch",
                            f"text states risk {claimed:g} for {tids[0]}, "
                            f"report has {actual_risk:g}",
                        )

    # -- structure ---------------------------------------------------------
    def walk(self, node: Any, path: str) -> None:
        if isinstance(node, Mapping):
            self._mapping(node, path)
        elif isinstance(node, Sequence) and not isinstance(node, str | bytes):
            for i, value in enumerate(node):
                self.walk(value, f"{path}[{i}]")
        elif isinstance(node, str):
            self.scan_text(path, node)

    def _mapping(self, node: Mapping[str, Any], path: str) -> None:
        keys = set(node)
        if "ref" in keys and ("kind" in keys or "note" in keys or len(keys) == 1):
            kind = node.get("kind")
            self.check_ref(f"{path}.ref", node["ref"], kind if isinstance(kind, str) else None)
        for key, value in node.items():
            sub = f"{path}.{key}"
            if key in _ID_FIELDS:
                if value is None:
                    continue
                values = value if isinstance(value, list) else [value]
                for i, v in enumerate(values):
                    self.check_ref(
                        f"{sub}[{i}]" if isinstance(value, list) else sub,
                        v,
                        _ID_FIELDS[key],
                        strict=True,
                    )
            elif key == "cites" and isinstance(value, list):
                for i, v in enumerate(value):
                    self.check_ref(f"{sub}[{i}]", v)
            elif key == "numbers" and isinstance(value, list):
                for i, v in enumerate(value):
                    self.check_number(f"{sub}[{i}]", v)
            elif key in _SKIP_SCAN:
                continue
            else:
                self.walk(value, sub)
        if self.require_citations:
            self._citations(node, path)

    def _citations(self, node: Mapping[str, Any], path: str) -> None:
        if "text" in node and "cites" in node:
            if not node.get("cites") and node.get("kind", "finding") != "context":
                self.add(path, "uncited", "claim cites no report id")
        elif "rationale" in node and not node.get("evidence") and not node.get("threat_id"):
            self.add(path, "uncited", "explained item has no evidence")


def _as_data(obj: Any) -> Any:
    return obj.model_dump(mode="json") if isinstance(obj, BaseModel) else obj


def check(obj: Any, index: ReportIndex, *, require_citations: bool = True) -> list[Issue]:
    """All grounding issues of ``obj`` (a pydantic model or JSON-like data)."""
    checker = _Checker(index, require_citations=require_citations)
    checker.walk(_as_data(obj), "$")
    seen: set[tuple[str, str]] = set()
    unique = []
    for issue in checker.issues:
        if (issue.path, issue.detail) not in seen:
            seen.add((issue.path, issue.detail))
            unique.append(issue)
    return unique


def feedback(issues: Sequence[Issue], limit: int = 25) -> str:
    """Retry prompt telling the model exactly what to fix."""
    lines = "\n".join(f"- {i.render()}" for i in issues[:limit])
    more = f"\n(+{len(issues) - limit} more)" if len(issues) > limit else ""
    return (
        "The output is not grounded in the report. Fix ONLY these problems: cite ids exactly "
        "as tools return them, copy numbers exactly, and remove anything the report does not "
        f"contain.\n{lines}{more}"
    )


_CLAIM_PATH = re.compile(r"^\$\.claims\[(\d+)\]")
_UNIT_PATH = re.compile(
    r"^(\$\.(?:claims|findings|remediation_plan|steps|reviews|assessments)\[\d+\])"
)


def result(obj: Any, index: ReportIndex, issues: Sequence[Issue] | None = None) -> GroundingResult:
    """A :class:`GroundingResult` for an assessment-shaped output."""
    found = list(issues) if issues is not None else check(obj, index)
    data = _as_data(obj)
    units: list[str] = []
    if isinstance(data, Mapping):
        for key in ("claims", "findings", "remediation_plan"):
            items = data.get(key)
            if isinstance(items, list):
                units.extend(f"$.{key}[{i}]" for i in range(len(items)))
    bad_units = {m.group(1) for i in found if (m := _UNIT_PATH.match(i.path))}
    if units:
        ratio = sum(1 for u in units if u not in bad_units) / len(units)
    else:
        ratio = 0.0 if found else 1.0
    out = []
    for issue in found:
        m = _CLAIM_PATH.match(issue.path)
        out.append(
            GroundingIssue(
                claim=int(m.group(1)) if m else -1,
                code=issue.code,
                detail=f"{issue.path}: {issue.detail}",
            )
        )
    return GroundingResult(passed=not found, grounded_ratio=round(ratio, 4), issues=out)


def attach_grounding(agent: Agent[Any, Any]) -> None:
    """Add the grounding output validator (retry with feedback, then flag) to ``agent``."""
    from pydantic_ai import ModelRetry, RunContext

    from startup_sbom.ai.tools import AgentDeps

    @agent.output_validator
    def _grounded(ctx: RunContext[AgentDeps], output: Any) -> Any:
        if not isinstance(output, BaseModel):
            return output
        issues = check(output, ctx.deps.index)
        if not issues:
            return output
        if ctx.retry < ctx.max_retries:  # accept (and flag) on the last attempt
            ctx.deps.note(f"grounding: {len(issues)} issue(s), asking the model to fix them")
            raise ModelRetry(feedback(issues))
        ctx.deps.note(f"grounding: {len(issues)} issue(s) remain; flagged in the result")
        return output
