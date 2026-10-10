"""Format registry, rendering entry point and atomic report writing."""

from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from startup_sbom.errors import OutputError
from startup_sbom.models import Report
from startup_sbom.report.cdxvex import render_cdx_vex
from startup_sbom.report.cyclonedx import render_cyclonedx
from startup_sbom.report.graphs import render_dot, render_mermaid
from startup_sbom.report.html import render_html
from startup_sbom.report.markdown import render_markdown
from startup_sbom.report.native import RenderOptions, render_native
from startup_sbom.report.openvex import render_openvex
from startup_sbom.report.sarif import render_sarif
from startup_sbom.report.spdx import render_spdx

FILE_MODE = 0o644


@dataclass(frozen=True, slots=True)
class FormatSpec:
    """An output format: its name, default file name and renderer."""

    name: str
    default_filename: str
    render: Callable[[Report, RenderOptions], str]
    description: str = ""


FORMATS: dict[str, FormatSpec] = {
    spec.name: spec
    for spec in (
        FormatSpec("json", "report.json", render_native, "native report (all analysis)"),
        FormatSpec("cyclonedx", "sbom.cdx.json", render_cyclonedx, "CycloneDX SBOM"),
        FormatSpec("spdx", "sbom.spdx.json", render_spdx, "SPDX 2.3 SBOM"),
        FormatSpec("sarif", "results.sarif", render_sarif, "SARIF 2.1.0 (code scanning)"),
        FormatSpec("openvex", "vex.openvex.json", render_openvex, "OpenVEX 0.2.0"),
        FormatSpec("cdx-vex", "vex.cdx.json", render_cdx_vex, "CycloneDX VEX"),
        FormatSpec("markdown", "report.md", render_markdown, "Markdown report (Mermaid)"),
        FormatSpec("html", "report.html", render_html, "self-contained HTML report"),
        FormatSpec("dot", "attack-graph.dot", render_dot, "Graphviz attack graph"),
        FormatSpec("mermaid", "attack-graph.mmd", render_mermaid, "Mermaid attack graph"),
    )
}


def render(report: Report, fmt: str, options: RenderOptions | None = None) -> str:
    """Render ``report`` in format ``fmt`` (a key of :data:`FORMATS`)."""
    spec = FORMATS.get(fmt)
    if spec is None:
        raise OutputError(f"unknown output format {fmt!r} (choose from {', '.join(FORMATS)})")
    return spec.render(report, options or RenderOptions())


def atomic_write(path: pathlib.Path, data: str) -> pathlib.Path:
    """Atomically replace ``path`` with ``data`` (UTF-8, mode 0644).

    The parent directory is created.  A symlink (or non-regular file) at the
    destination is refused; the temporary file lives in the same directory so the
    final :func:`os.replace` is atomic and never follows a destination symlink.
    """
    path = pathlib.Path(path)
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputError(f"cannot create output directory {parent}: {exc}") from exc
    if path.is_symlink():
        raise OutputError(f"refusing to write through a symlink: {path}")
    if path.exists() and not path.is_file():
        raise OutputError(f"output path exists and is not a regular file: {path}")
    try:
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as exc:
        raise OutputError(f"cannot write {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, FILE_MODE)
        if path.is_symlink():  # re-check: replacing a symlink would not follow it, but refuse
            raise OutputError(f"refusing to write through a symlink: {path}")
        os.replace(tmp, path)
    except OutputError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise OutputError(f"cannot write {path}: {exc}") from exc
    return path


def write_reports(
    report: Report,
    outputs: Mapping[str, pathlib.Path],
    options: RenderOptions | None = None,
) -> list[pathlib.Path]:
    """Render every ``format → path`` in ``outputs`` and write each atomically.

    All formats are rendered before anything is written, so a rendering error
    leaves no partial set of files.  Returns the written paths in input order.
    """
    opts = options or RenderOptions()
    seen: dict[str, str] = {}
    for fmt, dest in outputs.items():
        if fmt not in FORMATS:
            raise OutputError(f"unknown output format {fmt!r} (choose from {', '.join(FORMATS)})")
        key = os.path.normcase(os.path.abspath(dest))
        if key in seen:
            raise OutputError(f"formats {seen[key]!r} and {fmt!r} both write to {dest}")
        seen[key] = fmt
    rendered = [(pathlib.Path(dest), render(report, fmt, opts)) for fmt, dest in outputs.items()]
    return [atomic_write(dest, text) for dest, text in rendered]
