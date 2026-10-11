"""Render an :class:`~startup_sbom.models.AIAssessment` as JSON, text, Markdown or PDF.

Every string came from a model that read untrusted scan data, so it is sanitised
(control/bidi characters removed) and escaped for the target format.
"""

from __future__ import annotations

import re
import textwrap
from collections.abc import Sequence
from typing import Literal

from startup_sbom.ai import AIConfigError, AIUnavailableError
from startup_sbom.models import AIAssessment, Report
from startup_sbom.textsafe import clean

OutputFormat = Literal["json", "text", "markdown", "pdf"]
OUTPUT_FORMATS: tuple[str, ...] = ("json", "text", "markdown", "pdf")
WIDTH = 92
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+\-.!|~])")


def _t(value: object, max_len: int = 4_000) -> str:
    return clean(value, max_len=max_len, keep_newlines=True)


def _wrap(text: str, indent: str = "", width: int = WIDTH) -> str:
    out = [
        textwrap.fill(para, width=width, initial_indent=indent, subsequent_indent=indent)
        if para.strip()
        else ""
        for para in _t(text).split("\n")
    ]
    return "\n".join(out)


def _md(value: object, max_len: int = 4_000) -> str:
    """Escape Markdown/HTML metacharacters in one line of untrusted text."""
    return _MD_SPECIAL.sub(r"\\\1", clean(value, max_len=max_len))


def _md_block(value: object) -> str:
    return "\n".join(_md(line) for line in _t(value).split("\n"))


def _code(value: object) -> str:
    return clean(value, max_len=500).replace("`", "'")


def render_json(assessment: AIAssessment) -> str:
    return assessment.model_dump_json(indent=2) + "\n"


def render_text(assessment: AIAssessment) -> str:
    a = assessment
    lines = [
        "AI ASSESSMENT",
        f"provider: {_t(a.provider, 100)}   model: {_t(a.model, 200)}   audience: {a.audience}",
        f"generated: {a.generated.isoformat()}   input sha256: {a.input_sha256}",
        f"agents: {', '.join(_t(x, 60) for x in a.agents) or '-'}",
        _grounding_line(a),
        "",
        "EXECUTIVE SUMMARY",
        _wrap(a.executive_summary, "  "),
        "",
    ]
    if a.findings:
        lines.append("FINDINGS")
        for i, f in enumerate(a.findings, 1):
            tid = f" [{_t(f.threat_id, 120)}]" if f.threat_id else ""
            agree = "" if f.agrees_with_scanner else "  (disagrees with scanner)"
            lines.append(f"{i:>2}. {f.priority}{tid} {_t(f.title, 300)}{agree}")
            lines.append(_wrap(f.rationale, "      "))
            lines.append(f"      confidence {f.confidence:.2f}; evidence: {_refs(f.evidence)}")
            lines.extend(
                _wrap(f"if {c.condition}: {c.effect}", "      ~ ") for c in f.counterfactuals
            )
        lines.append("")
    if a.remediation_plan:
        lines.append("REMEDIATION PLAN")
        for i, s in enumerate(a.remediation_plan, 1):
            lines.append(f"{i:>2}. {_t(s.title, 300)}  (fixes: {', '.join(s.fixes) or '-'})")
            lines.append(_wrap(s.rationale, "      "))
            lines.extend(f"      $ {_t(cmd, 500)}" for cmd in s.commands)
        lines.append("")
    if a.caveats:
        lines.append("CAVEATS")
        lines.extend(_wrap(c, "  - ") for c in a.caveats)
        lines.append("")
    if a.grounding.issues:
        lines.append("GROUNDING ISSUES")
        lines.extend(_wrap(f"[{i.code}] {i.detail}", "  ! ") for i in a.grounding.issues)
        lines.append("")
    lines.extend([_wrap(a.disclaimer), _usage_line(a), ""])
    return "\n".join(lines)


def render_markdown(assessment: AIAssessment) -> str:
    a = assessment
    out = [
        "# AI assessment",
        "",
        f"*{_md(a.disclaimer)}*",
        "",
        "| | |",
        "|---|---|",
        f"| Provider / model | {_md(a.provider, 100)} / {_md(a.model, 200)} |",
        f"| Agents | {', '.join(_md(x, 60) for x in a.agents) or '-'} |",
        f"| Audience | {a.audience} |",
        f"| Generated | {a.generated.isoformat()} |",
        f"| Input SHA-256 | `{a.input_sha256}` |",
        f"| Grounding | {_md(_grounding_line(a))} |",
        "",
        "## Executive summary",
        "",
        _md_block(a.executive_summary),
        "",
    ]
    if a.findings:
        out += ["## Findings", ""]
        for f in a.findings:
            tid = f" — `{_code(f.threat_id)}`" if f.threat_id else ""
            out.append(f"### {f.priority}{tid}: {_md(f.title, 300)}")
            out.append("")
            out.append(_md_block(f.rationale))
            out.append("")
            out.append(
                f"- Confidence: {f.confidence:.2f}"
                + ("" if f.agrees_with_scanner else " (disagrees with the scanner)")
            )
            out.append(
                "- Evidence: "
                + ", ".join(f"`{_code(e.ref)}` ({_md(e.kind, 40)})" for e in f.evidence)
            )
            out.extend(
                f"- *If* {_md(c.condition, 500)} *then* {_md(c.effect, 500)}"
                for c in f.counterfactuals
            )
            out.append("")
    if a.remediation_plan:
        out += ["## Remediation plan", ""]
        for i, s in enumerate(a.remediation_plan, 1):
            fixes = ", ".join(f"`{_code(x)}`" for x in s.fixes) or "-"
            out.append(
                f"{i}. **{_md(s.title, 300)}** (fixes {fixes}, confidence {s.confidence:.2f})"
            )
            out.append(f"   {_md(s.rationale, 2_000)}")
            if s.commands:
                out.append("")
                out.append("   ```sh")
                out.extend(f"   {_code(cmd)}" for cmd in s.commands)
                out.append("   ```")
        out.append("")
    if a.claims:
        out += ["## Claims", "", "| # | Kind | Claim | Cites |", "|---|---|---|---|"]
        for i, c in enumerate(a.claims):
            cites = ", ".join(f"`{_code(x)}`" for x in c.cites) or "-"
            out.append(f"| {i} | {c.kind} | {_md(c.text, 600)} | {cites} |")
        out.append("")
    if a.caveats:
        out += ["## Caveats", ""] + [f"- {_md(c, 1_000)}" for c in a.caveats] + [""]
    if a.grounding.issues:
        out += ["## Grounding issues", ""]
        out += [f"- **{i.code}** {_md(i.detail, 500)}" for i in a.grounding.issues]
        out.append("")
    out += [f"<sub>{_md(_usage_line(a))}</sub>", ""]
    return "\n".join(out)


def _refs(evidence: Sequence[object]) -> str:
    return ", ".join(_t(getattr(e, "ref", e), 200) for e in evidence) or "-"


def _grounding_line(a: AIAssessment) -> str:
    state = "passed" if a.grounding.passed else f"FLAGGED ({len(a.grounding.issues)} issue(s))"
    return f"grounding: {state}, grounded ratio {a.grounding.grounded_ratio:.0%}"


def _usage_line(a: AIAssessment) -> str:
    u = a.usage
    cost = f", est. ${u['est_cost_usd']:.4f}" if "est_cost_usd" in u else ""
    return (
        f"usage: {int(u.get('requests', 0))} request(s), {int(u.get('tool_calls', 0))} tool "
        f"call(s), {int(u.get('total_tokens', 0))} token(s){cost}"
    )


def render_pdf(assessment: AIAssessment, report: Report) -> bytes:
    """PDF of the report with ``report.ai`` set (needs the ``pdf`` extra/renderer)."""
    try:
        from startup_sbom.report import render_bytes
    except ImportError as exc:  # pragma: no cover - depends on the report package version
        raise AIUnavailableError("this build has no PDF renderer") from exc
    from startup_sbom.errors import OutputError

    with_ai = report.model_copy(update={"ai": assessment})
    try:
        return render_bytes(with_ai, "pdf")
    except OutputError as exc:
        raise AIUnavailableError(
            f"PDF output is unavailable: {exc} (pip install 'startup-sbom[pdf]')"
        ) from exc
    except ImportError as exc:
        raise AIUnavailableError("PDF output needs: pip install 'startup-sbom[pdf]'") from exc


def render_assessment(
    assessment: AIAssessment, fmt: str = "json", *, report: Report | None = None
) -> str | bytes:
    """Render ``assessment`` as ``json``/``text``/``markdown`` (str) or ``pdf`` (bytes)."""
    if fmt == "json":
        return render_json(assessment)
    if fmt == "text":
        return render_text(assessment)
    if fmt in ("markdown", "md"):
        return render_markdown(assessment)
    if fmt == "pdf":
        if report is None:
            raise AIConfigError("PDF output needs the report the assessment belongs to")
        return render_pdf(assessment, report)
    raise AIConfigError(f"unknown output format {fmt!r} (choose from {', '.join(OUTPUT_FORMATS)})")
