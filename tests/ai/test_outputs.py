"""Rendering AIAssessment as json / text / markdown (and pdf when the extra exists)."""

from __future__ import annotations

import json
import re

import pytest
from canned import good_assessment

from startup_sbom.ai import AIConfigError, AIUnavailableError
from startup_sbom.ai.agents import FinalAssessment
from startup_sbom.ai.index import ReportIndex
from startup_sbom.ai.orchestrator import to_assessment
from startup_sbom.ai.outputs import render_assessment
from startup_sbom.models import AIAssessment, Report

USAGE = {"requests": 3.0, "tool_calls": 4.0, "total_tokens": 1500.0, "est_cost_usd": 0.0123}


@pytest.fixture
def assessment(index: ReportIndex) -> AIAssessment:
    final = FinalAssessment.model_validate(good_assessment())
    return to_assessment(
        final,
        index,
        provider="anthropic",
        model="anthropic:claude-haiku-4-5",
        agents=["triage"],
        audience="technical",
        usage=USAGE,
    )


def test_render_json(assessment: AIAssessment, report: Report) -> None:
    data = json.loads(render_assessment(assessment, "json", report=report))
    assert data["provider"] == "anthropic"
    assert data["grounding"]["passed"] is True
    assert data["findings"][0]["threat_id"] == "TH-0001"
    assert data["input_sha256"] == assessment.input_sha256


def test_render_text(assessment: AIAssessment) -> None:
    text = render_assessment(assessment, "text")
    assert isinstance(text, str)
    assert "EXECUTIVE SUMMARY" in text
    assert "REMEDIATION PLAN" in text
    assert "$ apt-get install --only-upgrade openssh-server" in text
    assert "grounding: passed" in text
    assert "est. $0.0123" in text
    assert "\x1b" not in text


def test_render_markdown(assessment: AIAssessment) -> None:
    md = render_assessment(assessment, "markdown")
    assert isinstance(md, str)
    assert md.startswith("# AI assessment")
    assert "## Findings" in md
    assert "## Claims" in md
    assert "```sh" in md
    assert "`TH-0001`" in md
    assert render_assessment(assessment, "md") == md


def test_markdown_escapes_hostile_model_text(index: ReportIndex) -> None:
    payload = good_assessment()
    payload["executive_summary"] = "evil <img src=x onerror=alert(1)> *bold* [link](x)"
    final = FinalAssessment.model_validate(payload)
    hostile = to_assessment(
        final, index, provider="p", model="m", agents=[], audience="technical", usage={}
    )
    md = render_assessment(hostile, "markdown")
    assert isinstance(md, str)
    assert not re.search(r"(?<!\\)<img", md)  # every "<" is backslash-escaped
    assert r"\<img" in md
    assert r"\*bold\*" in md


def test_grounding_issues_rendered(index: ReportIndex) -> None:
    payload = good_assessment()
    payload["claims"].append(
        {"text": "invented CVE-2098-1111", "cites": ["TH-0001"], "numbers": [], "kind": "finding"}
    )
    final = FinalAssessment.model_validate(payload)
    flagged = to_assessment(
        final, index, provider="p", model="m", agents=[], audience="technical", usage={}
    )
    assert not flagged.grounding.passed
    text = render_assessment(flagged, "text")
    assert isinstance(text, str)
    assert "GROUNDING ISSUES" in text
    assert "CVE-2098-1111" in text
    md = render_assessment(flagged, "markdown")
    assert isinstance(md, str)
    assert "## Grounding issues" in md


def test_render_errors(assessment: AIAssessment) -> None:
    with pytest.raises(AIConfigError, match="unknown output format"):
        render_assessment(assessment, "docx")
    with pytest.raises(AIConfigError, match="needs the report"):
        render_assessment(assessment, "pdf")


def test_render_pdf_or_skip(assessment: AIAssessment, report: Report) -> None:
    try:
        pdf = render_assessment(assessment, "pdf", report=report)
    except AIUnavailableError as exc:
        pytest.skip(f"pdf renderer unavailable: {exc}")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
