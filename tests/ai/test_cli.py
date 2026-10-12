"""The ``startup-sbom ai`` Typer app: analyze/agents/providers/mcp/serve glue."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from canned import good_assessment
from typer.testing import CliRunner

import startup_sbom.ai.cli as cli_mod
from startup_sbom.ai.agents import FinalAssessment
from startup_sbom.ai.index import ReportIndex
from startup_sbom.ai.orchestrator import to_assessment
from startup_sbom.models import AIAssessment, Report

runner = CliRunner()


@pytest.fixture
def report_file(report: Report, tmp_path: Path) -> Path:
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


def canned_assessment(report: Report) -> AIAssessment:
    index = ReportIndex(report)
    return to_assessment(
        FinalAssessment.model_validate(good_assessment()),
        index,
        provider="test",
        model="test",
        agents=["triage"],
        audience="technical",
        usage={"requests": 2.0},
    )


def test_providers_lists_every_provider() -> None:
    result = runner.invoke(cli_mod.app, ["providers"])
    assert result.exit_code == 0, result.output
    out = result.output
    for needle in (
        "anthropic:claude-haiku-4-5",
        "anthropic:claude-sonnet-5",
        "anthropic:claude-opus-5",
        "openai:gpt-6-luna",
        "google:gemini-3.1-flash-lite",
        "groq:openai/gpt-oss-20b",
        "mistral:mistral-small-latest",
        "openrouter:openai/gpt-oss-20b",
        "ollama:",
    ):
        assert needle in out, needle
    assert "$1/$5 per MTok" in out
    assert "set ANTHROPIC_API_KEY" in out  # conftest cleared the env


def test_agents_lists_builtins() -> None:
    result = runner.invoke(cli_mod.app, ["agents"])
    assert result.exit_code == 0, result.output
    for name in ("triage", "exploitability", "attack_chains", "supply_chain", "remediation"):
        assert name in result.output
    assert "builtin" in result.output


def test_analyze_writes_output(
    report: Report, report_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import startup_sbom.ai.orchestrator as orch

    captured: dict = {}

    def fake_analyze(rep: Report, **kw: object) -> AIAssessment:
        captured.update(kw)
        return canned_assessment(rep)

    monkeypatch.setattr(orch, "analyze", fake_analyze)
    out_file = tmp_path / "assessment.md"
    result = runner.invoke(
        cli_mod.app,
        [
            "analyze",
            str(report_file),
            "--model",
            "test",
            "--agents",
            "triage,remediation",
            "--profile",
            "balanced",
            "--max-cost",
            "0.25",
            "--no-web-search",
            "-f",
            "markdown",
            "-o",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["model"] == "test"
    assert captured["agents"] == ["triage", "remediation"]
    assert captured["profile"] == "balanced"
    assert captured["max_cost_usd"] == 0.25
    assert captured["web_search"] is False
    text = out_file.read_text(encoding="utf-8")
    assert text.startswith("# AI assessment")
    assert "TH-0001" in text


def test_analyze_prints_to_stdout(report_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import startup_sbom.ai.orchestrator as orch

    monkeypatch.setattr(orch, "analyze", lambda rep, **kw: canned_assessment(rep))
    result = runner.invoke(cli_mod.app, ["analyze", str(report_file), "-f", "text", "--quiet"])
    assert result.exit_code == 0, result.output
    assert "EXECUTIVE SUMMARY" in result.output


def test_analyze_failures(report_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # pdf needs -o
    result = runner.invoke(cli_mod.app, ["analyze", str(report_file), "-f", "pdf"])
    assert result.exit_code == 2
    assert "--output" in result.output

    import startup_sbom.ai.orchestrator as orch
    from startup_sbom.ai import AIConfigError

    def boom(rep: Report, **kw: object) -> AIAssessment:
        raise AIConfigError("no AI provider configured")

    monkeypatch.setattr(orch, "analyze", boom)
    result = runner.invoke(cli_mod.app, ["analyze", str(report_file)])
    assert result.exit_code == 2
    assert "no AI provider configured" in result.output

    missing = runner.invoke(cli_mod.app, ["analyze", str(report_file) + ".nope"])
    assert missing.exit_code != 0


def test_analyze_grounding_warning(
    report: Report, report_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import startup_sbom.ai.orchestrator as orch

    flagged = canned_assessment(report)
    flagged = flagged.model_copy(
        update={
            "grounding": flagged.grounding.model_copy(
                update={"passed": False, "grounded_ratio": 0.5}
            )
        }
    )
    monkeypatch.setattr(orch, "analyze", lambda rep, **kw: flagged)
    result = runner.invoke(cli_mod.app, ["analyze", str(report_file), "--quiet"])
    assert result.exit_code == 0
    assert "grounding issue(s) flagged" in result.output


def test_mcp_requires_report_or_allow_scan() -> None:
    result = runner.invoke(cli_mod.app, ["mcp"])
    assert result.exit_code == 2
    assert "--report" in result.output
    assert "--allow-scan" in result.output


def test_serve_refuses_public_bind_without_token(report_file: Path) -> None:
    result = runner.invoke(
        cli_mod.app,
        ["serve", "--report", str(report_file), "--host", "0.0.0.0"],  # noqa: S104
    )
    assert result.exit_code == 2
    assert "STARTUP_SBOM_AGENT_TOKEN" in result.output


def test_invalid_report_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(cli_mod.app, ["analyze", str(bad)])
    assert result.exit_code == 2
    assert "error:" in result.output


def test_assessment_fixture_is_fresh(report: Report) -> None:
    a = canned_assessment(report)
    assert a.generated.tzinfo is not None
    assert (datetime.now(UTC) - a.generated).total_seconds() < 60
