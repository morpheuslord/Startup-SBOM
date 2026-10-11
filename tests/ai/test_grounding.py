"""Grounding: invented ids, wrong numbers, retry-then-flag validator behaviour."""

from __future__ import annotations

import asyncio

from canned import bad_assessment, good_assessment
from pydantic_ai import ModelResponse, RetryPromptPart, ToolCallPart
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models.function import AgentInfo, FunctionModel

from startup_sbom.ai import grounding as gr
from startup_sbom.ai.agents import FinalAssessment, make_agent
from startup_sbom.ai.index import ReportIndex
from startup_sbom.ai.tools import AgentDeps


def codes(issues: list[gr.Issue]) -> set[str]:
    return {i.code for i in issues}


def test_good_assessment_is_grounded(index: ReportIndex) -> None:
    assert gr.check(good_assessment(), index) == []


def test_invented_cve_in_text(index: ReportIndex) -> None:
    issues = gr.check({"text": "exposed through CVE-2099-0001", "cites": ["TH-0001"]}, index)
    assert codes(issues) == {"unknown_id"}
    assert "CVE-2099-0001" in issues[0].detail


def test_unknown_ghsa_cwe_attack_ids(index: ReportIndex) -> None:
    issues = gr.check(
        {
            "text": "see GHSA-2222-3333-4444, CWE-9999 and T9999",
            "cites": ["TH-0001"],
        },
        index,
    )
    details = " | ".join(i.detail for i in issues)
    assert "GHSA-2222-3333-4444" in details
    assert "CWE-9999" in details
    assert "T9999" in details
    # ids that ARE in the report pass
    assert gr.check({"text": "CWE-364 via T1190", "cites": ["TH-0001"]}, index) == []


def test_wrong_number_caught(index: ReportIndex) -> None:
    claim = {
        "text": "risk of TH-0001",
        "cites": ["TH-0001"],
        "numbers": [{"ref": "TH-0001", "field": "risk_score", "value": 50.0}],
    }
    issues = gr.check(claim, index)
    assert codes(issues) == {"numeric_mismatch"}
    assert "92.5" in issues[0].detail

    ok = {
        "text": "risk of TH-0001",
        "cites": ["TH-0001"],
        "numbers": [{"ref": "TH-0001", "field": "risk_score", "value": 92.5}],
    }
    assert gr.check(ok, index) == []


def test_number_with_unknown_ref(index: ReportIndex) -> None:
    claim = {
        "text": "x",
        "cites": ["TH-0001"],
        "numbers": [{"ref": "TH-9999", "field": "risk_score", "value": 1.0}],
    }
    assert codes(gr.check(claim, index)) == {"unknown_number_ref"}


def test_percentage_tolerance(index: ReportIndex) -> None:
    # EPSS 0.43 stated as "43%" in text is accepted; a wrong EPSS is not.
    ok = {"text": "EPSS 43% for CVE-2024-6387.", "cites": ["CVE-2024-6387"]}
    assert gr.check(ok, index) == []
    bad = {"text": "EPSS 0.9 for CVE-2024-6387.", "cites": ["CVE-2024-6387"]}
    assert codes(gr.check(bad, index)) == {"numeric_mismatch"}


def test_strict_id_fields(index: ReportIndex) -> None:
    item = {
        "threat_id": "TH-9999",
        "fixes": ["TH-0001", "TH-8888"],
        "rationale": "r",
        "evidence": [{"ref": "TH-0001", "kind": "threat"}],
    }
    issues = gr.check(item, index)
    details = " | ".join(i.detail for i in issues)
    assert "'TH-9999'" in details
    assert "'TH-8888'" in details
    assert "'TH-0001'" not in details


def test_uncited_claim_flagged(index: ReportIndex) -> None:
    issues = gr.check({"text": "something bad", "cites": []}, index)
    assert codes(issues) == {"uncited"}
    # context claims need no citation
    assert gr.check({"text": "background", "cites": [], "kind": "context"}, index) == []


def test_result_ratio_and_claim_mapping(index: ReportIndex) -> None:
    good = gr.result(good_assessment(), index)
    assert good.passed
    assert good.grounded_ratio == 1.0
    assert good.issues == []

    bad = gr.result(bad_assessment(), index)
    assert not bad.passed
    assert 0.0 <= bad.grounded_ratio < 1.0
    assert all(i.claim == -1 for i in bad.issues)  # no claims array entries were bad

    with_claims = good_assessment()
    with_claims["claims"].append(
        {
            "text": "nonsense citing nothing real",
            "cites": ["TH-4242"],
            "numbers": [],
            "kind": "finding",
        }
    )
    res = gr.result(with_claims, index)
    assert any(i.claim == 1 for i in res.issues)


def test_feedback_lists_problems(index: ReportIndex) -> None:
    text = gr.feedback(gr.check(bad_assessment(), index))
    assert "CVE-2099-0001" in text
    assert "not grounded" in text


# --------------------------------------------------------------------------- validator
def _scripted(payloads: list[dict]) -> FunctionModel:
    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        step = len([m for m in messages if m.kind == "response"])
        payload = payloads[min(step, len(payloads) - 1)]
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, payload)])

    return FunctionModel(fn)


def test_validator_retries_then_accepts_fix(index: ReportIndex) -> None:
    agent = make_agent(
        _scripted([bad_assessment(), good_assessment()]),
        name="t",
        output_type=FinalAssessment,
        instructions="x",
    )
    deps = AgentDeps(index=index)
    result = asyncio.run(agent.run("go", deps=deps))
    assert result.output.findings[0].threat_id == "TH-0001"
    retry_parts = [
        p
        for m in result.all_messages()
        if m.kind == "request"
        for p in m.parts
        if isinstance(p, RetryPromptPart)
    ]
    assert retry_parts, "the grounding validator never asked for a retry"
    assert "CVE-2099-0001" in str(retry_parts[0].content)
    assert gr.result(result.output, index).passed


def test_validator_flags_after_exhausted_retries(index: ReportIndex) -> None:
    agent = make_agent(
        _scripted([bad_assessment()]),  # never fixes it
        name="t",
        output_type=FinalAssessment,
        instructions="x",
    )
    deps = AgentDeps(index=index)
    result = asyncio.run(agent.run("go", deps=deps))
    # accepted on the last attempt instead of crashing ...
    assert result.output.executive_summary.startswith("The system is exposed")
    # ... and the problems are flagged in the GroundingResult
    flagged = gr.result(result.output, index)
    assert not flagged.passed
    assert {i.code for i in flagged.issues} >= {"unknown_id", "numeric_mismatch"}
    assert any("flagged" in c for c in deps.calls)
