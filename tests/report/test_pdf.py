"""PDF report: Typst rendering, sandboxing, determinism, registry and engine fallback."""

from __future__ import annotations

import json
import re
import shutil
import socket
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from reportdata import SSHD, build_report

from startup_sbom.errors import OutputError
from startup_sbom.models import (
    AIAssessment,
    AICounterfactual,
    AIEvidenceRef,
    AIFinding,
    AIRemediationStep,
    DecisionNode,
    Driver,
    Explanation,
    ExplanationMethod,
    Explanations,
    ExploitRef,
    Factor,
    Fix,
    GlobalExplanation,
    GroundingIssue,
    GroundingResult,
    IntelBundle,
    IntelRecord,
    PocRepo,
    Report,
    SSVCTrace,
    VendorStatus,
    WhatIf,
)
from startup_sbom.report import FORMATS, RenderOptions, render, render_bytes, write_reports
from startup_sbom.report.pdf import PdfOptions, render_pdf
from startup_sbom.report.pdf import engine as pdf_engine
from startup_sbom.report.pdf.viewmodel import build_view_model, https_url

ATTACK = (
    '#read("/etc/passwd") ] $x^2$ `raw` <lbl> @ref \u202eevil\u202c #panic("boom") *b* _i_ // c'
)
TEMPLATES = pdf_engine.TEMPLATES
WHEN = datetime(2026, 10, 10, 12, 30, tzinfo=UTC)


def _trace(outcome: str, tag: str = "") -> SSVCTrace:
    def node(point: str, value: str, alts: list[str], why: str) -> DecisionNode:
        return DecisionNode(decision_point=point, value=value, alternatives=alts, rationale=why)

    return SSVCTrace(
        tree="cisa-coordinator/2.0.3",
        path=[
            node("Exploitation", "active", ["none", "public_poc"], "Listed in CISA KEV" + tag),
            node("Automatable", "no", ["yes"], "Race condition needs many attempts"),
            node("Technical impact", "total", ["partial"], "root code execution"),
            node("Mission & well-being", "high", ["low", "medium"], "network-exposed sshd"),
        ],
        row=35,
        outcome=outcome,
        flips=["Exploitation=none would give Attend" + tag],
    )


def enrich(report: Report, tag: str = "") -> Report:
    """Add explanations, SSVC traces, intel and an AI assessment to a fixture report."""
    r = report.model_copy(deep=True)
    t1 = next(t for t in r.threats if t.id == "TH-0001")
    t1.explanation = Explanation(
        subject="TH-0001",
        method=ExplanationMethod.SEQUENTIAL_LMDI,
        formula="risk = 100 × severity × reach × exploit × exposure" + tag,
        baseline=10.0,
        total=92.5,
        factors=[
            Factor(
                name="cvss",
                label="CVSS 8.1" + tag,
                value=8.1,
                kind="multiplicative",
                multiplier=1.6,
                contribution=30.0,
            ),
            Factor(
                name="reach",
                label="network service",
                value="network_service",
                kind="multiplicative",
                multiplier=1.4,
                contribution=25.0,
            ),
            Factor(name="kev", label="CISA KEV", value=True, kind="additive", contribution=20.0),
            Factor(name="epss", label="EPSS 0.43", value=0.43, kind="additive", contribution=12.5),
            Factor(
                name="hardening", label="hardening", value=None, kind="additive", contribution=-5.0
            ),
        ],
        limits=["Exposure assumes the default sshd_config" + tag],
    )
    assert t1.ssvc is not None
    t1.ssvc.trace = _trace("Act", tag)
    t1.ssvc.bod_26_04 = _trace("Immediate", tag)
    t1.intel_summary = "Weaponised exploits are public." + tag
    t1.mitigations = ["MaxStartups limits concurrent races" + tag]
    t1.stride = ["E", "T"]
    r.intel = [
        IntelBundle(
            cve="CVE-2024-6387",
            exploit_maturity="weaponized",
            exploitation="active",
            exploit_available=True,
            exploit_sources=["metasploit", "exploitdb"],
            metasploit=[
                ExploitRef(
                    source="metasploit",
                    id="exploit/linux/ssh/regresshion",
                    title="regreSSHion" + tag,
                    url="https://www.rapid7.com/db/x/",
                    verified=True,
                )
            ],
            exploitdb=[ExploitRef(source="exploitdb", id="52000", url="javascript:alert(1)")],
            poc_repos_count=42,
            poc_repos_top=[
                PocRepo(
                    full_name="someone/regresshion-poc" + tag,
                    url="https://github.com/someone/regresshion-poc",
                    stars=900,
                )
            ],
            vendor_status=[
                VendorStatus(
                    vendor="debian",
                    status="fixed",
                    severity="high",
                    statement="Fixed in DSA-5724-1" + tag,
                    url="http://insecure.example/dsa",
                )
            ],
            advisories=[
                IntelRecord(
                    id="r1",
                    source="osv",
                    url="https://security-tracker.debian.org/x",
                    kind="advisory",
                    title="CVE-2024-6387" + tag,
                    site="debian",
                    fetched_at=WHEN,
                )
            ],
            epss_trend=[("2026-10-01", 0.41), ("2026-10-09", 0.43)],
            errors=["nuclei: timeout"],
            fetched_at=WHEN,
        )
    ]
    chain = next(c for c in r.attack_chains if c.id == "AC-0002")
    chain.explanation = Explanation(
        subject="AC-0002",
        method=ExplanationMethod.NOISY_OR_LOG,
        formula="score = 100 × likelihood × impact",
        baseline=0.0,
        total=90.0,
        factors=[
            Factor(name="step1", label="regreSSHion", kind="additive", contribution=70.0),
            Factor(name="impact", label="root impact", kind="additive", contribution=20.0),
        ],
    )
    r.explanations = Explanations(
        system=GlobalExplanation(
            system_risk=87.3,
            formula="1 − Π(1 − rᵢ)",
            drivers=[
                Driver(
                    kind="chain",
                    id="AC-0002",
                    label="Direct root via sshd" + tag,
                    contribution=40.0,
                    share=0.46,
                    cumulative=0.46,
                ),
                Driver(
                    kind="threat",
                    id="TH-0002",
                    label="xz backdoor",
                    contribution=30.0,
                    share=0.34,
                    cumulative=0.80,
                ),
                Driver(
                    kind="vendor",
                    id="Tukaani",
                    label="Tukaani",
                    contribution=5.0,
                    share=0.06,
                    cumulative=0.86,
                ),
            ],
            pareto_80={"chain": 1, "threat": 1},
        ),
        fixes=[
            Fix(
                id="FIX-1",
                kind="upgrade",
                target=SSHD,
                action="Upgrade openssh-server" + tag,
                resolves=["TH-0001"],
            ),
            Fix(
                id="FIX-2",
                kind="hardening",
                target="systemd:ssh.service",
                action="Set NoNewPrivileges=yes",
                breaks=["step-x"],
            ),
        ],
        fix_plan=[
            WhatIf(
                fixes=["FIX-1", "FIX-2"],
                chains_broken=["AC-0001", "AC-0002"],
                threats_resolved=["TH-0001"],
                risk_before=87.3,
                risk_after=31.0,
                method="greedy_set_cover",
                note="Covers every ranked chain" + tag,
            )
        ],
        what_if=[
            WhatIf(
                fixes=["FIX-1"],
                chains_broken=["AC-0002"],
                threats_resolved=["TH-0001"],
                risk_before=87.3,
                risk_after=52.0,
                method="single",
            )
        ],
    )
    r.ai = AIAssessment(
        provider="anthropic",
        model="claude-test" + tag,
        agents=["triage", "remediation"],
        generated=WHEN,
        input_sha256="ab" * 32,
        executive_summary="Patch sshd first.\n\nThen remove the backdoored liblzma." + tag,
        findings=[
            AIFinding(
                threat_id="TH-0001",
                title="Internet-facing sshd is exploitable" + tag,
                priority="P1",
                evidence=[
                    AIEvidenceRef(ref="TH-0001", kind="threat"),
                    AIEvidenceRef(ref="CVE-2024-6387", kind="cve", note="KEV" + tag),
                    AIEvidenceRef(ref="systemd:ssh.service", kind="service"),
                    AIEvidenceRef(ref="CVE-9999-0000" + tag, kind="cve"),
                ],
                rationale="Pre-auth RCE on a root service." + tag,
                confidence=0.9,
                counterfactuals=[
                    AICounterfactual(condition="sshd bound to loopback", effect="drops to Attend")
                ],
            ),
            AIFinding(
                title="Unknown threat cited",
                priority="P3",
                threat_id="TH-404",
                agrees_with_scanner=False,
                rationale="Hallucinated.",
                confidence=0.2,
            ),
        ],
        remediation_plan=[
            AIRemediationStep(
                title="Upgrade openssh-server" + tag,
                commands=["apt-get install --only-upgrade openssh-server" + tag],
                fixes=["TH-0001"],
                evidence=[AIEvidenceRef(ref="AC-0002", kind="chain")],
                rationale="Closes AC-0002.",
                confidence=0.8,
            )
        ],
        caveats=["No runtime telemetry was available" + tag],
        grounding=GroundingResult(
            passed=False,
            grounded_ratio=0.75,
            issues=[
                GroundingIssue(
                    claim=0, code="unknown_id", detail="CVE-9999-0000 not in report" + tag
                )
            ],
        ),
    )
    return r


def rich() -> Report:
    return enrich(build_report())


def hostile() -> Report:
    r = enrich(build_report(hostile=True), tag=" " + ATTACK)
    r.threats[0].title += ATTACK
    r.threats[0].narrative += "\n\n" + ATTACK
    r.attack_chains[0].narrative += ATTACK
    r.attack_chains[0].steps[0].title += ATTACK
    r.metadata.target.reference += ATTACK
    r.vulnerabilities[0].references.insert(0, "javascript:alert(1)")
    return r


def _pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf))


def _query(report: Report, selector: str, field: str | None = None) -> Any:
    typst = pytest.importorskip("typst")
    vm = build_view_model(report)
    out = typst.query(
        str(TEMPLATES / pdf_engine.MAIN),
        selector,
        field=field,
        root=str(TEMPLATES),
        ignore_system_fonts=True,
        sys_inputs={"data": json.dumps(vm, ensure_ascii=False)},
    )
    return json.loads(out)


def _texts(node: Any) -> list[str]:
    if isinstance(node, dict):
        return [s for v in node.values() for s in _texts(v)]
    if isinstance(node, list):
        return [s for v in node for s in _texts(v)]
    return [node] if isinstance(node, str) else []


# --------------------------------------------------------------------------- rendering
def test_rich_report_renders_deterministic_pdfa() -> None:
    pytest.importorskip("typst")
    report = rich()
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert 8 <= _pages(pdf) <= 30
    assert render_pdf(report) == pdf  # byte-identical
    shuffled = report.model_copy(deep=True)
    for lst in (shuffled.packages, shuffled.vulnerabilities, shuffled.threats, shuffled.services):
        lst.reverse()
    assert render_pdf(shuffled) == pdf  # independent of analysis order
    assert b"pdfaid" in pdf  # PDF/A-3u + PDF/UA-1 identification
    assert b"pdfuaid" in pdf
    assert b"/StructTreeRoot" in pdf  # tagged
    assert b"/Lang" in pdf
    assert b"/CreationDate(D:20261010120005Z)" in pdf  # fixed from metadata.finished
    assert pdf.count(b"/EmbeddedFile") >= 2
    assert b"report.json" in pdf
    assert b"ai-assessment.json" in pdf


def test_sections_and_ai_marker() -> None:
    sections = _query(rich(), "<sbom-section>", "value")
    for name in (
        "summary",
        "threats",
        "chains",
        "fixes",
        "supply",
        "services",
        "ai",
        "coverage",
        "vulns",
        "methodology",
        "notices",
    ):
        assert name in sections
    plain = _query(build_report(), "<sbom-section>", "value")
    assert "ai" not in plain
    assert "fixes" not in plain


def test_hostile_strings_render_literally() -> None:
    pytest.importorskip("typst")
    report = hostile()
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF-")
    assert b"root:x:0:0" not in pdf
    heads = " ".join(_texts(_query(report, "heading", "body")))
    assert '#read("/etc/passwd")' in heads
    assert "#panic(" in heads
    assert "$x^2$" in heads
    assert "\u202e" not in heads
    assert "\u202c" not in heads
    pars = " ".join(_texts(_query(report, "par", "body")))
    assert "evil</script>" in pars or "evil</script>" in heads


def test_empty_report_renders() -> None:
    pytest.importorskip("typst")
    empty = Report(metadata=build_report().metadata)
    pdf = render_bytes(empty, "pdf")
    assert pdf.startswith(b"%PDF-")
    assert 4 <= _pages(pdf) <= 10


@pytest.mark.parametrize("profile", ["accessible", "plain"])
def test_profiles(profile: str) -> None:
    pytest.importorskip("typst")
    pdf = render_pdf(rich(), pdf=PdfOptions(profile=profile, paper="us-letter"))  # type: ignore[arg-type]
    assert pdf.startswith(b"%PDF-")
    assert b"pdfaid" not in pdf


# --------------------------------------------------------------------------- view model
def test_view_model_sanitises_and_resolves() -> None:
    vm = build_view_model(hostile())
    blob = json.dumps(vm, ensure_ascii=False)
    assert "\u202e" not in blob
    assert "\x07" not in blob
    assert "javascript:" not in blob
    assert "http://insecure" not in blob
    ai = vm["ai"]
    states = {e["id"]: e["state"] for e in ai["findings"][0]["evidence"]}
    assert states["TH-0001"] == "linked"
    assert states["CVE-2024-6387"] == "linked"
    assert states["systemd:ssh.service"] == "linked"
    assert any(s == "unknown" for i, s in states.items() if i.startswith("CVE-9999"))
    assert "TH-404" in ai["unknown"]
    labels = [t["anchor"] for t in vm["threats"]] + [v["anchor"] for v in vm["vulns"]]
    assert len(labels) == len(set(labels))
    assert all(re.fullmatch(r"[a-z]+-[0-9a-f]{12}(-\d+)?", a) for a in labels)
    chart = vm["threats"][0]["chart"]
    assert chart["exact"]
    assert [r["delta"] for r in chart["rows"]][-1] == "92.5"
    assert all(0 <= r["x0"] <= 1 and 0 < r["w"] <= 1 for r in chart["rows"])
    exploits = vm["threats"][0]["intel"]["bundle"]["exploits"]
    assert [e["url"] for e in exploits] == ["https://www.rapid7.com/db/x/", None]


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://osv.dev/vulnerability/CVE-2024-6387", True),
        ("http://example.org/", False),
        ("javascript:alert(1)", False),
        ("https://user@evil.example/", False),
        ("https://exa mple.org/", False),
        ("https://example.org/\u202e", False),
        ("https:///nohost", False),
    ],
)
def test_https_only_links(url: str, ok: bool) -> None:
    assert (https_url(url) == url) is ok


def test_templates_never_evaluate_or_fetch() -> None:
    files = {p.name: p.read_text(encoding="utf-8") for p in TEMPLATES.glob("*.typ")}
    assert set(files) == {"report.typ", "components.typ"}
    for name, src in files.items():
        code = "\n".join(line.split("//", 1)[0] for line in src.splitlines())
        for banned in ("eval(", "@preview", 'import "@', "plugin(", "image(", "include "):
            assert banned not in code, (name, banned)
        imports = re.findall(r'#import\s+"([^"]+)"', code)
        assert set(imports) <= {"components.typ"}
    assert files["report.typ"].count("read(") == 1  # only via load() with fixed names
    loaded = set(re.findall(r'load\("[^"]+", "([^"]+)"\)', files["report.typ"]))
    assert loaded == set(pdf_engine.INPUT_FILES.values())


# --------------------------------------------------------------------------- registry
def test_registry_and_text_api() -> None:
    spec = FORMATS["pdf"]
    assert spec.binary
    assert spec.default_filename == "report.pdf"
    assert not FORMATS["json"].binary
    report = build_report()
    with pytest.raises(OutputError, match="binary"):
        render(report, "pdf")
    with pytest.raises(OutputError, match="binary"):
        spec.render(report, RenderOptions())
    assert render_bytes(report, "markdown") == render(report, "markdown").encode("utf-8")
    with pytest.raises(OutputError, match="unknown"):
        render_bytes(report, "docx")


def test_write_reports_pdf_and_json(tmp_path: Path) -> None:
    pytest.importorskip("typst")
    report = rich()
    out = {"pdf": tmp_path / "o" / "report.pdf", "json": tmp_path / "o" / "report.json"}
    assert write_reports(report, out) == list(out.values())
    assert out["pdf"].read_bytes() == render_pdf(report)
    assert out["json"].read_text(encoding="utf-8") == render(report, "json")
    if sys.platform != "win32":
        assert stat.S_IMODE(out["pdf"].stat().st_mode) == 0o644
    assert sorted(p.name for p in (tmp_path / "o").iterdir()) == ["report.json", "report.pdf"]


# --------------------------------------------------------------------------- engines
def test_missing_engine_raises_install_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(sys.modules, "typst", None)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(OutputError, match=r"pip install 'startup-sbom\[pdf\]'"):
        render_pdf(build_report())
    with pytest.raises(OutputError, match="startup-sbom"):  # nothing half-written
        write_reports(build_report(), {"json": tmp_path / "r.json", "pdf": tmp_path / "r.pdf"})
    assert list(tmp_path.iterdir()) == []


FAKE_TYPST = """#!{python}
import json, pathlib, sys
argv = sys.argv[1:]
root = pathlib.Path(argv[argv.index("--root") + 1])
data = json.loads((root / "data.json").read_text(encoding="utf-8"))
native = json.loads((root / "attach-report.json").read_text(encoding="utf-8"))
record = {{
    "argv": argv,
    "files": sorted(p.name for p in root.iterdir()),
    "title": data["title"],
    "attach": native["metadata"]["scan_id"],
    "ai_empty": (root / "attach-ai.json").read_text(encoding="utf-8") == "",
}}
pathlib.Path({log!r}).write_text(json.dumps(record), encoding="utf-8")
pathlib.Path(argv[-1]).write_bytes(b"%PDF-1.7 fake\\n%%EOF\\n")
"""


@pytest.mark.skipif(sys.platform == "win32", reason="shebang executables")
def test_cli_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    log = tmp_path / "log.json"
    exe = tmp_path / "bin" / "typst"
    exe.parent.mkdir()
    exe.write_text(FAKE_TYPST.format(python=sys.executable, log=str(log)), encoding="utf-8")
    exe.chmod(0o755)
    monkeypatch.setitem(sys.modules, "typst", None)
    monkeypatch.setattr(shutil, "which", lambda name: str(exe) if name == "typst" else None)

    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    made: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def tracking_mkdtemp(**kw: Any) -> str:
        made.append(real_mkdtemp(**kw))
        return made[-1]

    monkeypatch.setattr(tempfile, "mkdtemp", tracking_mkdtemp)
    report = build_report()
    assert render_pdf(report) == b"%PDF-1.7 fake\n%%EOF\n"

    rec = json.loads(log.read_text(encoding="utf-8"))
    argv = rec["argv"]
    root = made[0]
    assert argv[0] == "compile"
    assert argv[argv.index("--root") + 1] == root
    assert "--ignore-system-fonts" in argv
    assert argv[argv.index("--pdf-standard") + 1] == "a-3u,ua-1"
    assert argv[argv.index("--creation-timestamp") + 1] == str(
        int(datetime(2026, 10, 10, 12, 0, 5, tzinfo=UTC).timestamp())
    )
    assert argv[argv.index("mode=files") - 1 : argv.index("mode=files") + 1] == [
        "--input",
        "mode=files",
    ]
    assert argv[-2] == str(Path(root) / "report.typ")
    assert argv[-1].startswith(root)
    assert all(
        not a.startswith(root) or ".packages" in a or a.endswith((".typ", ".pdf")) or a == root
        for a in argv
    )
    assert not any("http" in a or "@preview" in a or "{" in a for a in argv)  # no data in argv
    assert {"report.typ", "components.typ", "data.json", "attach-report.json"} <= set(rec["files"])
    assert rec["title"] == "Startup-SBOM Security Report"
    assert rec["ai_empty"]
    assert rec["attach"] == report.metadata.scan_id
    assert not Path(root).exists()  # temp root removed


@pytest.mark.skipif(sys.platform == "win32", reason="shebang executables")
def test_cli_failure_is_output_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    exe = tmp_path / "typst"
    exe.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stderr.write('boom\\x1b[2J')\nsys.exit(3)\n"
    )
    exe.chmod(0o755)
    monkeypatch.setitem(sys.modules, "typst", None)
    monkeypatch.setattr(shutil, "which", lambda name: str(exe))
    with pytest.raises(OutputError, match="exit 3") as info:
        render_pdf(build_report())
    assert "\x1b" not in str(info.value)


@pytest.mark.skipif(shutil.which("typst") is None, reason="typst CLI not installed")
def test_real_cli_matches_python_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("typst")
    report = rich()
    expected = render_pdf(report)
    monkeypatch.setitem(sys.modules, "typst", None)
    assert render_pdf(report).startswith(b"%PDF-")
    assert expected.startswith(b"%PDF-")


def test_cjk_summary_falls_back_to_plain_profile(report):
    """Glyphs absent from the bundled fonts must not abort archival rendering."""
    pytest.importorskip("typst")
    report = report.model_copy(deep=True)
    report.vulnerabilities[0].summary = "credited to 朱恺乾、others"
    data = render_pdf(report)
    assert data.startswith(b"%PDF")
