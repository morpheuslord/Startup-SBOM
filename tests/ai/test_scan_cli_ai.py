"""`startup-sbom scan --ai/--ai-live/--journal`: AI wiring of the scan command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from canned import good_assessment
from typer.testing import CliRunner

from startup_sbom import cli
from startup_sbom.models import AIAssessment, Report

runner = CliRunner()
BASE = ["--sources", "none", "--no-eol", "--no-epss", "--no-kev", "--no-language-packages"]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "root"
    (r / "etc").mkdir(parents=True)
    (r / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
    return r


def test_ai_assessment_is_stored_in_the_report(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import startup_sbom.ai as ai_pkg

    seen: dict[str, object] = {}

    def fake_analyze(report: Report, **kw: object) -> AIAssessment:
        seen.update(kw)
        stream = kw["stream"]
        assert callable(stream)
        stream("delegating to triage")
        from startup_sbom.ai.agents import FinalAssessment
        from startup_sbom.ai.index import ReportIndex
        from startup_sbom.ai.orchestrator import to_assessment

        return to_assessment(
            FinalAssessment.model_validate(good_assessment()),
            ReportIndex(report),
            provider="test",
            model="test",
            agents=["triage"],
            audience="technical",
            usage={"requests": 1.0},
        )

    monkeypatch.setattr(ai_pkg, "analyze", fake_analyze, raising=False)
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        ["scan", f"dir:{root}", *BASE, "--ai", "--ai-model", "test", "--ai-profile",
         "balanced", "--ai-max-cost", "0.5", "-f", "json", "-o", str(out), "--no-live"],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "ai: delegating to triage" in result.output
    data = json.loads((out / "report.json").read_text())
    assert data["ai"]["provider"] == "test"
    assert seen["profile"] == "balanced"
    assert seen["max_cost_usd"] == 0.5


def test_ai_failure_becomes_a_warning(
    root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import startup_sbom.ai as ai_pkg
    from startup_sbom.ai import AIConfigError

    def broken(report: Report, **kw: object) -> AIAssessment:
        raise AIConfigError("no AI provider configured")

    monkeypatch.setattr(ai_pkg, "analyze", broken, raising=False)
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app, ["scan", f"dir:{root}", *BASE, "--ai", "-f", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads((out / "report.json").read_text())
    assert any("AI assessment failed" in w for w in data["warnings"])


def test_ai_refuses_offline(root: Path) -> None:
    result = runner.invoke(cli.app, ["scan", f"dir:{root}", *BASE, "--offline", "--ai"])
    assert result.exit_code == 2


def test_ai_live_and_journal(root: Path, tmp_path: Path) -> None:
    journal = tmp_path / "scan.jsonl"
    result = runner.invoke(
        cli.app,
        ["scan", f"dir:{root}", *BASE, "--ai-live", "--ai-model", "test",
         "--journal", str(journal)],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "Live analyst notes" in result.output
    kinds = {json.loads(line)["kind"] for line in journal.read_text().splitlines()}
    assert {"stage", "digest", "analyst-done"} <= kinds
