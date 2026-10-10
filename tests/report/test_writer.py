"""Format registry, native JSON + schema, determinism and atomic writing."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import jsonschema
import pytest
from reportdata import build_report

from startup_sbom.errors import OutputError
from startup_sbom.models import Report
from startup_sbom.report import (
    FORMATS,
    RenderOptions,
    canonical,
    json_schema,
    render,
    write_reports,
)

EXPECTED = {
    "json": "report.json",
    "cyclonedx": "sbom.cdx.json",
    "spdx": "sbom.spdx.json",
    "sarif": "results.sarif",
    "openvex": "vex.openvex.json",
    "cdx-vex": "vex.cdx.json",
    "markdown": "report.md",
    "html": "report.html",
    "dot": "attack-graph.dot",
    "mermaid": "attack-graph.mmd",
}


def _shuffled(report: Report) -> Report:
    """The same report with every top-level list reversed."""
    r = report.model_copy(deep=True)
    for lst in (r.packages, r.services, r.binaries, r.vulnerabilities, r.threats, r.attack_chains):
        lst.reverse()
    sc = r.supply_chain
    for lst2 in (sc.vendors, sc.findings, sc.blast_radius, sc.nodes, sc.edges):
        lst2.reverse()
    for p in r.packages:
        p.depends.reverse()
    for v in r.vulnerabilities:
        v.cvss.reverse()
    return r


def test_registry() -> None:
    assert {k: v.default_filename for k, v in FORMATS.items()} == EXPECTED
    for name, spec in FORMATS.items():
        assert spec.name == name
        assert callable(spec.render)


@pytest.mark.parametrize("fmt", sorted(EXPECTED))
def test_every_format_renders_deterministically(report: Report, fmt: str) -> None:
    first = render(report, fmt)
    assert first.strip()
    assert first.endswith("\n")
    assert render(report, fmt) == first
    assert render(_shuffled(report), fmt) == first  # independent of analysis order


@pytest.mark.parametrize("fmt", sorted(EXPECTED))
def test_every_format_handles_empty_report(fmt: str) -> None:
    base = build_report()
    empty = Report(metadata=base.metadata)
    assert render(empty, fmt).strip()


def test_render_does_not_mutate_input(report: Report) -> None:
    shuffled = _shuffled(report)
    before = shuffled.model_dump_json()
    for fmt in EXPECTED:
        render(shuffled, fmt)
    assert shuffled.model_dump_json() == before
    assert canonical(shuffled).model_dump_json() == canonical(report).model_dump_json()


def test_unknown_format(report: Report) -> None:
    with pytest.raises(OutputError):
        render(report, "xml")


def test_native_json_and_schema(report: Report) -> None:
    schema = json.loads(json_schema())
    assert schema["$id"] == "https://github.com/morpheuslord/Startup-SBOM/schema/report-2.0.json"
    assert schema["title"]
    doc = json.loads(render(report, "json"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert [p["id"] for p in doc["packages"]] == sorted(p.id for p in report.packages)
    assert [t["id"] for t in doc["threats"]] == sorted(t.id for t in report.threats)
    assert Report.model_validate(doc) == canonical(report)  # lossless round trip


# --------------------------------------------------------------------------- writing
def test_write_reports(report: Report, tmp_path: Path) -> None:
    outputs = {fmt: tmp_path / "out" / "nested" / name for fmt, name in EXPECTED.items()}
    written = write_reports(report, outputs, RenderOptions(cdx_spec="1.7"))
    assert written == list(outputs.values())
    for fmt, path in outputs.items():
        assert path.read_text(encoding="utf-8") == render(
            report, fmt, RenderOptions(cdx_spec="1.7")
        )
        if sys.platform != "win32":
            assert stat.S_IMODE(path.stat().st_mode) == 0o644
    leftovers = [p.name for p in (tmp_path / "out" / "nested").iterdir() if p.name.startswith(".")]
    assert leftovers == []


def test_write_overwrites_atomically(report: Report, tmp_path: Path) -> None:
    dest = tmp_path / "report.md"
    dest.write_text("old", encoding="utf-8")
    write_reports(report, {"markdown": dest})
    assert dest.read_text(encoding="utf-8").startswith("# Startup-SBOM report")


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_write_refuses_symlink(report: Report, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    link = tmp_path / "report.json"
    os.symlink(victim, link)
    with pytest.raises(OutputError, match="symlink"):
        write_reports(report, {"json": link})
    assert victim.read_text(encoding="utf-8") == "precious"
    assert link.is_symlink()
    dangling = tmp_path / "sbom.cdx.json"
    os.symlink(tmp_path / "does-not-exist", dangling)
    with pytest.raises(OutputError, match="symlink"):
        write_reports(report, {"cyclonedx": dangling})
    assert not (tmp_path / "does-not-exist").exists()


def test_write_refuses_directory_and_bad_input(report: Report, tmp_path: Path) -> None:
    (tmp_path / "dir").mkdir()
    with pytest.raises(OutputError):
        write_reports(report, {"json": tmp_path / "dir"})
    with pytest.raises(OutputError, match="unknown"):
        write_reports(report, {"pdf": tmp_path / "x.pdf"})
    with pytest.raises(OutputError, match="both write"):
        write_reports(report, {"json": tmp_path / "a", "markdown": tmp_path / "a"})
    assert not (tmp_path / "a").exists()  # validation happens before any write
