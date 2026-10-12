"""End-to-end analyze(), delegation with grounding, and the usage/cost guard."""

from __future__ import annotations

import asyncio

import pytest
from canned import bad_triage, good_assessment, good_triage
from pydantic_ai import ModelResponse, ToolCallPart, UsageLimitExceeded
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.usage import RunUsage

from startup_sbom.ai import AIBudgetError, AIConfigError
from startup_sbom.ai.orchestrator import (
    ModelSet,
    analyze_async,
    input_sha256,
    make_guard,
    usage_dict,
)
from startup_sbom.ai.registry import AgentRegistry, builtin_specs
from startup_sbom.models import AIAssessment, Report


def scripted_models(*, triage_payload: dict | None = None, delegate: bool = True) -> ModelSet:
    """One FunctionModel for both roles, dispatching on the agent's toolset."""

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        step = len([m for m in messages if m.kind == "response"])
        tool_names = [t.name for t in info.function_tools]
        output_tool = info.output_tools[0].name
        if any(n.startswith("ask_") for n in tool_names):  # the orchestrator
            if step == 0:
                return ModelResponse(parts=[ToolCallPart("get_summary", {})])
            if step == 1 and delegate:
                return ModelResponse(
                    parts=[ToolCallPart("ask_triage", {"task": "rank the threats"})]
                )
            return ModelResponse(parts=[ToolCallPart(output_tool, good_assessment())])
        # a specialist (triage)
        return ModelResponse(parts=[ToolCallPart(output_tool, triage_payload or good_triage())])

    return ModelSet.single(FunctionModel(fn))


def run_analyze(report: Report, **kw) -> AIAssessment:
    registry = AgentRegistry(builtin_specs())
    kw.setdefault("models", scripted_models())
    kw.setdefault("registry", registry)
    kw.setdefault("agents", ["triage"])
    kw.setdefault("max_cost_usd", None)
    kw.setdefault("web_search", False)
    return asyncio.run(analyze_async(report, **kw))


def test_analyze_end_to_end(report: Report) -> None:
    notes: list[str] = []
    assessment = run_analyze(report, stream=notes.append)
    assert isinstance(assessment, AIAssessment)
    assert assessment.provider == "test"
    assert assessment.model == "test"
    assert assessment.agents == ["triage"]
    assert assessment.grounding.passed
    assert assessment.grounding.grounded_ratio == 1.0
    assert assessment.findings[0].threat_id == "TH-0001"
    assert assessment.findings[0].priority == "P1"
    assert assessment.remediation_plan[0].fixes == ["TH-0001"]
    assert assessment.claims[0].numbers[0].value == 92.5
    assert assessment.input_sha256 == input_sha256(report)
    assert assessment.usage["requests"] >= 3  # orchestrator (3 steps) + specialist
    assert any("ask_triage" in n for n in notes)
    assert any("tool get_summary" in n for n in notes)


def test_specialist_grounding_issue_becomes_caveat(report: Report) -> None:
    assessment = run_analyze(report, models=scripted_models(triage_payload=bad_triage()))
    assert assessment.grounding.passed  # the orchestrator's own output is fine
    assert any("triage" in c and "ungrounded" in c for c in assessment.caveats)


def test_analyze_without_delegation(report: Report) -> None:
    assessment = run_analyze(report, models=scripted_models(delegate=False))
    assert assessment.agents == []  # nothing consulted
    assert assessment.grounding.passed


def test_unknown_audience_and_agent(report: Report) -> None:
    with pytest.raises(AIConfigError, match="audience"):
        run_analyze(report, audience="board")
    with pytest.raises(AIConfigError, match="unknown agent"):
        run_analyze(report, agents=["nope"])


def test_input_sha256_excludes_ai_and_is_stable(report: Report) -> None:
    first = input_sha256(report)
    assert len(first) == 64
    assessment = run_analyze(report)
    with_ai = report.model_copy(update={"ai": assessment})
    assert input_sha256(with_ai) == first


# --------------------------------------------------------------------------- cost guard
def test_cost_guard_stops_on_usd_ceiling() -> None:
    guard = make_guard(0.5, ("anthropic:claude-opus-5",))
    usage = RunUsage(requests=1, input_tokens=1_000_000, output_tokens=0)  # ~$5 on opus-5
    with pytest.raises(UsageLimitExceeded, match="max_cost_usd"):
        guard.check_cost(usage)
    with pytest.raises(UsageLimitExceeded, match="would exceed"):
        guard.check_before_request(usage)
    # under the ceiling nothing happens
    guard.check_cost(RunUsage(requests=1, input_tokens=1_000, output_tokens=100))


def test_cost_guard_without_price_or_ceiling() -> None:
    free = make_guard(None, ())
    free.check_cost(RunUsage(requests=1, input_tokens=10**9, output_tokens=10**9))
    unpriced = make_guard(0.01, ("unknown:model",))
    unpriced.check_cost(RunUsage(requests=1, input_tokens=10**9, output_tokens=0))


def test_usage_limit_becomes_budget_error(report: Report) -> None:
    limits = make_guard(None, (), request_limit=1)
    with pytest.raises(AIBudgetError, match="stopped"):
        run_analyze(report, limits=limits)


def test_usage_dict_contents() -> None:
    guard = make_guard(1.0, ("anthropic:claude-haiku-4-5",))
    usage = RunUsage(
        requests=3, tool_calls=5, input_tokens=10_000, output_tokens=2_000, cache_read_tokens=1_000
    )
    out = usage_dict(usage, guard)
    assert out["requests"] == 3.0
    assert out["tool_calls"] == 5.0
    assert out["total_tokens"] == 12_000.0
    assert out["max_cost_usd"] == 1.0
    assert 0 < out["est_cost_usd"] < 1


# --------------------------------------------------------------------------- sync wrapper
def test_sync_analyze_wrapper(report: Report, monkeypatch: pytest.MonkeyPatch) -> None:
    import startup_sbom.ai.orchestrator as orch

    captured: dict = {}

    async def fake_async(rep: Report, **kw) -> str:  # type: ignore[override]
        captured.update(kw)
        return "sentinel"

    monkeypatch.setattr(orch, "analyze_async", fake_async)
    monkeypatch.setenv("STARTUP_SBOM_AI_PLUGINS", "compliance , extra")
    monkeypatch.setenv("STARTUP_SBOM_AI_AGENT_URLS", "https://a.example")
    result = orch.analyze(report, profile="balanced", agents=["triage"], web_search=False)
    assert result == "sentinel"
    assert captured["profile"] == "balanced"
    assert captured["plugins"] == ["compliance", "extra"]
    assert captured["remote_agents"] == ["https://a.example"]
    assert captured["web_search"] is False
