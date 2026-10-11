"""Pure TUI state: form mapping, CLI preview, recent scans, report IO, ps parsing."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from startup_sbom.models import Report
from startup_sbom.tui import state
from startup_sbom.tui.state import (
    FormValues,
    RecentStore,
    TuiError,
    build_request,
    compose_target,
    entry_for,
    equivalent_cli,
    list_containers,
    load_report,
    parse_ps_output,
    split_target,
    validate_values,
)


# --------------------------------------------------------------------- mapping
def test_build_request_defaults_match_cli_defaults(tmp_path: Path) -> None:
    values = FormValues(target=f"dir:{tmp_path}")
    req = build_request(values, env={})
    opts = req.options
    assert opts.vuln_sources == ("osv", "arch")  # the CLI --sources default
    assert opts.offline is False
    assert opts.epss
    assert opts.kev
    assert opts.eol
    assert opts.language_packages
    assert opts.link_analysis
    assert not opts.integrity_check
    assert opts.nvd_api_key is None
    assert opts.cache_dir is None
    assert opts.platform is None
    assert opts.boot_timing_file is None
    assert opts.vex_not_affected_unreachable is False
    assert opts.prefetch_intel is False
    assert req.formats == ("json",)
    assert req.output_dir == Path("startup-sbom-out")
    assert req.fail_on == "none"
    assert req.cdx_spec == "1.6"
    assert req.ai.enabled is False


def test_build_request_full_mapping(tmp_path: Path) -> None:
    timing = tmp_path / "blame.txt"
    timing.write_text("1.0s ssh.service\n")
    values = FormValues(
        target=f"dir:{tmp_path}",
        offline=False,
        sources=("nvd", "osv"),
        epss=False,
        kev=False,
        eol=False,
        language_packages=False,
        link_analysis=False,
        integrity=True,
        platform="linux/arm64",
        boot_timing=str(timing),
        cdx_spec="1.7",
        vex_unreachable=True,
        formats=("json", "sarif", "json"),
        output_dir=str(tmp_path / "out"),
        fail_on="act",
        prefetch_intel=True,
        intel_max_cves=7,
        intel_max_articles=2,
        intel_budget=30.0,
        intel_articles=False,
        ai_enabled=True,
        ai_provider="anthropic",
        ai_model="claude-x",
        ai_profile="quality",
        ai_audience="executive",
        ai_max_cost=2.5,
    )
    req = build_request(values, env={"NVD_API_KEY": "k", "STARTUP_SBOM_CACHE_DIR": "/tmp/c"})
    opts = req.options
    assert opts.vuln_sources == ("osv", "nvd")  # canonical order, deduped
    assert opts.nvd_api_key == "k"
    assert opts.cache_dir == Path("/tmp/c")
    assert (opts.epss, opts.kev, opts.eol) == (False, False, False)
    assert opts.integrity_check
    assert not opts.language_packages
    assert not opts.link_analysis
    assert opts.platform == "linux/arm64"
    assert opts.boot_timing_file == timing
    assert opts.vex_not_affected_unreachable is True
    assert opts.prefetch_intel is True
    assert (opts.intel_max_cves, opts.intel_max_articles) == (7, 2)
    assert opts.intel_budget == 30.0
    assert opts.intel_articles is False
    assert req.formats == ("json", "sarif")
    assert req.fail_on == "act"
    assert req.cdx_spec == "1.7"
    assert req.vex_unreachable
    assert req.ai.enabled
    assert req.ai.provider == "anthropic"
    assert req.ai.model == "claude-x"
    assert req.ai.profile == "quality"
    assert req.ai.audience == "executive"
    assert req.ai.max_cost_usd == 2.5


def test_offline_disables_intel_and_ai(tmp_path: Path) -> None:
    values = FormValues(
        target=f"dir:{tmp_path}", offline=True, prefetch_intel=True, ai_enabled=True
    )
    req = build_request(values, env={})
    assert req.options.offline is True
    assert req.options.prefetch_intel is False
    assert req.ai.enabled is False


def test_equivalent_cli_minimal_and_full(tmp_path: Path) -> None:
    minimal = equivalent_cli(FormValues(target="dir:/x"))
    assert minimal == "startup-sbom scan dir:/x -f json -o startup-sbom-out"
    values = FormValues(
        target="dir:/x",
        offline=True,
        sources=("osv",),
        epss=False,
        integrity=True,
        platform="linux/arm64",
        formats=("json", "sarif"),
        fail_on="high",
        cdx_spec="1.7",
        vex_unreachable=True,
    )
    cli = equivalent_cli(values)
    for part in (
        "--offline",
        "--sources osv",
        "--no-epss",
        "--integrity",
        "--platform linux/arm64",
        "-f sarif",
        "--fail-on high",
        "--cdx-spec 1.7",
        "--vex-unreachable-not-affected",
    ):
        assert part in cli, cli
    # intel/AI flags appear only when enabled and online
    on = replace(values, offline=False, prefetch_intel=True, ai_enabled=True, ai_provider="openai")
    cli_on = equivalent_cli(on)
    assert "--intel" in cli_on
    assert "--ai" in cli_on
    assert "--ai-provider openai" in cli_on
    assert "--intel" not in cli
    assert "--ai" not in cli


def test_compose_split_target_roundtrip() -> None:
    assert compose_target("host", "ignored") == "host:"
    assert compose_target("auto", " /x ") == "/x"
    assert compose_target("oci-archive", " img.tar ") == "oci-archive:img.tar"
    assert split_target("docker:web") == ("docker", "web")
    assert split_target("host:") == ("host", "")
    assert split_target("/plain/path") == ("auto", "/plain/path")
    assert split_target("") == ("dir", "")


def test_validate_values_reports_every_problem(tmp_path: Path) -> None:
    good = FormValues(target=f"dir:{tmp_path}")
    assert validate_values(good) == []
    bad = FormValues(
        target=f"dir:{tmp_path}/does-not-exist",
        platform="not a platform",
        boot_timing=str(tmp_path / "missing.txt"),
        intel_max_cves=0,
        intel_budget=-1.0,
    )
    errors = validate_values(bad)
    joined = "\n".join(errors)
    assert "target:" in joined
    assert "platform:" in joined
    assert "boot-timing" in joined
    assert "max CVEs" in joined
    assert "budget" in joined


def test_validate_values_requires_output_dir_for_formats(tmp_path: Path) -> None:
    values = FormValues(target=f"dir:{tmp_path}", formats=("json",), output_dir="  ")
    assert any("output directory" in e for e in validate_values(values))


# --------------------------------------------------------------------- containers
def test_parse_ps_output_jsonl_and_array() -> None:
    jsonl = (
        '{"ID":"abc123def456789","Names":"web","Image":"nginx:1.25","State":"running"}\n'
        '{"ID":"fff","Names":["/a","/b"],"Image":"redis","Status":"Exited"}\n'
    )
    rows = parse_ps_output("docker", jsonl)
    assert [r.name for r in rows] == ["web", "a,/b"]
    assert rows[0].id == "abc123def456"  # truncated to 12
    assert rows[0].state == "running"
    array = json.dumps([{"Id": "1234", "Names": ["pod"], "Image": "img", "State": "created"}])
    rows = parse_ps_output("podman", array)
    assert rows[0].name == "pod"
    assert rows[0].engine == "podman"
    assert parse_ps_output("docker", "") == []
    with pytest.raises(TuiError):
        parse_ps_output("docker", "not json {")


def test_list_containers_safe_invocation(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TuiError, match="unsupported engine"):
        list_containers("rm -rf /")  # never reaches a shell

    monkeypatch.setattr(state.shutil, "which", lambda engine: f"/usr/bin/{engine}")
    calls: list[list[str]] = []

    def runner(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout='{"ID":"x","Names":"n"}\n', stderr="")

    rows = list_containers("docker", runner=runner)
    assert rows[0].name == "n"
    assert calls[0][0] == "/usr/bin/docker"
    assert calls[0][1:] == [
        "ps",
        "-a",
        "--format",
        "{{json .}}",
    ]

    def failing(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="permission denied")

    with pytest.raises(TuiError, match="permission denied"):
        list_containers("docker", runner=failing)


# --------------------------------------------------------------------- recent store
def test_recent_store_roundtrip(tmp_path: Path, report: Report) -> None:
    store = RecentStore(tmp_path / "data")
    assert store.load() == []
    a = entry_for(report, tmp_path / "a.json")
    b = entry_for(report, tmp_path / "b.json")
    store.add(a)
    store.add(b)
    store.add(a)  # dedupe: a moves to the top
    entries = store.load()
    assert [e.path for e in entries] == [a.path, b.path]
    assert entries[0].threats == report.summary.threats
    store.remove(b.path)
    assert [e.path for e in store.load()] == [a.path]


def test_recent_store_ignores_corrupt_file(tmp_path: Path) -> None:
    store = RecentStore(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{broken json", encoding="utf-8")
    assert store.load() == []
    store.path.write_text('[{"no_path": 1}, 42]', encoding="utf-8")
    assert store.load() == []


# --------------------------------------------------------------------- reports
def test_load_report_roundtrip(tmp_path: Path, report: Report) -> None:
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    loaded = load_report(path)
    assert loaded.summary.threats == report.summary.threats
    assert loaded.metadata.scan_id == report.metadata.scan_id


def test_load_report_rejects_bad_input(tmp_path: Path, report: Report) -> None:
    with pytest.raises(TuiError, match="cannot open"):
        load_report(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(TuiError, match="not valid JSON"):
        load_report(bad)
    not_report = tmp_path / "x.json"
    not_report.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(TuiError, match="not a startup-sbom report"):
        load_report(not_report)
    big = tmp_path / "big.json"
    big.write_text("[]", encoding="utf-8")
    with pytest.raises(TuiError, match="larger than"):
        load_report(big, max_bytes=1)
    old = json.loads(report.model_dump_json())
    old["metadata"]["schema_version"] = "1.0"
    versioned = tmp_path / "old.json"
    versioned.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(TuiError, match=r"schema 1\.0"):
        load_report(versioned)
