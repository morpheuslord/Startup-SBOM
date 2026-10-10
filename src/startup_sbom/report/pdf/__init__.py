"""PDF report (optional extra ``startup-sbom[pdf]``) rendered with Typst.

The report is converted to a sanitised JSON view model
(:func:`~startup_sbom.report.pdf.viewmodel.build_view_model`) and laid out by the
bundled Typst templates, which never interpret data as markup.  Output is tagged
PDF/UA-1 and, by default, PDF/A-3u with ``report.json`` (and the AI assessment,
when present) embedded as attachments.  Bytes are deterministic for a given report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from startup_sbom.errors import OutputError
from startup_sbom.models import Report
from startup_sbom.report.native import RenderOptions, render_native, utc
from startup_sbom.report.pdf.engine import CompileJob, compile_pdf
from startup_sbom.report.pdf.viewmodel import build_view_model

PdfProfile = Literal["archival", "accessible", "plain"]
PROFILES: dict[str, tuple[str, ...]] = {
    "archival": ("a-3u", "ua-1"),  # PDF/A-3u permits the JSON attachments
    "accessible": ("ua-1",),
    "plain": (),
}


@dataclass(frozen=True, slots=True)
class PdfOptions:
    """PDF-specific knobs (the shared :class:`RenderOptions` has none yet)."""

    profile: PdfProfile = "archival"
    paper: Literal["a4", "us-letter"] = "a4"
    attach_json: bool = True
    max_rows: int = 5000  # vulnerability inventory rows; the attachment has all
    top_threats: int = 10
    top_chains: int = 6


def render_pdf(
    report: Report,
    options: RenderOptions | None = None,
    *,
    pdf: PdfOptions | None = None,
) -> bytes:
    """Render ``report`` as PDF bytes.

    Raises :class:`~startup_sbom.errors.OutputError` when no Typst engine is
    available (install hint included) or compilation fails.
    """
    opts = options or RenderOptions()
    p = pdf or PdfOptions()
    if p.profile not in PROFILES:
        raise OutputError(f"unknown PDF profile {p.profile!r} (choose {', '.join(PROFILES)})")
    if p.paper not in ("a4", "us-letter"):
        raise OutputError(f"unknown paper size {p.paper!r}")
    vm = build_view_model(
        report, max_rows=max(0, p.max_rows), top_threats=p.top_threats, top_chains=p.top_chains
    )
    inputs = {"data": json.dumps(vm, ensure_ascii=False, separators=(",", ":")), "paper": p.paper}
    if p.attach_json:
        inputs["attach-report"] = render_native(report, opts)
        if report.ai is not None:
            inputs["attach-ai"] = report.ai.model_dump_json(indent=2) + "\n"
    stamp = utc(report.metadata.finished or report.metadata.started).replace(microsecond=0)
    try:
        return compile_pdf(
            CompileJob(inputs=inputs, standards=PROFILES[p.profile], timestamp=stamp)
        )
    except OutputError as exc:
        # Real scan data may carry glyphs (e.g. CJK names in CVE credits) that the
        # bundled fonts lack; the strict PDF/A + PDF/UA profiles refuse those.
        # Retry once as a plain PDF, which renders them as fallback glyphs.
        if p.profile == "plain" or "could not be displayed with font" not in str(exc):
            raise
        return compile_pdf(CompileJob(inputs=inputs, standards=PROFILES["plain"], timestamp=stamp))


__all__ = ["PROFILES", "PdfOptions", "PdfProfile", "render_pdf"]
