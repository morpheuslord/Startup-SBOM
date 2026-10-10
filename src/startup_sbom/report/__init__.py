"""Report rendering: native JSON, CycloneDX, SPDX, SARIF, VEX, Markdown, HTML, graphs.

Every format renders from the same :class:`~startup_sbom.models.Report`::

    from startup_sbom.report import RenderOptions, render, write_reports

    print(render(report, "markdown"))
    write_reports(report, {"cyclonedx": Path("out/sbom.cdx.json")}, RenderOptions(cdx_spec="1.7"))
"""

from __future__ import annotations

from startup_sbom.report.console import print_console
from startup_sbom.report.native import RenderOptions, canonical, json_schema
from startup_sbom.report.writer import FORMATS, FormatSpec, atomic_write, render, write_reports

__all__ = [
    "FORMATS",
    "FormatSpec",
    "RenderOptions",
    "atomic_write",
    "canonical",
    "json_schema",
    "print_console",
    "render",
    "write_reports",
]
