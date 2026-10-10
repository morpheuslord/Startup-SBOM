"""Typst compilation backends: the ``typst`` Python package, else the official CLI.

Neither backend downloads anything.  The template directory is the compile root,
so Typst ``read()`` calls cannot reach scan output or host files; data arrives as
JSON through ``sys.inputs`` (Python package) or as files in a private temporary
root (CLI fallback).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from startup_sbom.errors import OutputError
from startup_sbom.textsafe import clean

TEMPLATES = Path(__file__).resolve().parent / "templates"
MAIN = "report.typ"
#: sys.inputs key -> fixed file name in the CLI root (the template reads these names only).
INPUT_FILES = {
    "data": "data.json",
    "attach-report": "attach-report.json",
    "attach-ai": "attach-ai.json",
}
INSTALL_HINT = (
    "PDF output needs Typst: pip install 'startup-sbom[pdf]' "
    "(or put the official typst CLI on PATH)"
)
CLI_TIMEOUT = 180.0


@dataclass(frozen=True, slots=True)
class CompileJob:
    """Everything one compilation needs (all strings already sanitised JSON)."""

    inputs: Mapping[str, str]  # keys of INPUT_FILES (+ small scalar settings)
    standards: Sequence[str]
    timestamp: datetime


def _error(exc: Exception, what: str) -> OutputError:
    detail = str(getattr(exc, "diagnostic", None) or getattr(exc, "message", None) or exc)
    return OutputError(
        f"PDF rendering failed ({what}): {clean(detail, max_len=2000, keep_newlines=True)}"
    )


def compile_pdf(job: CompileJob) -> bytes:
    """Compile with the ``typst`` package, else the ``typst`` CLI, else fail with a hint."""
    try:
        import typst
    except ImportError:
        exe = shutil.which("typst")
        if exe is None:
            raise OutputError(INSTALL_HINT) from None
        return compile_cli(exe, job)
    try:
        compiler = typst.Compiler(root=str(TEMPLATES), font_paths=[], ignore_system_fonts=True)
        out = compiler.compile(
            input=str(TEMPLATES / MAIN),
            format="pdf",
            sys_inputs=dict(job.inputs),
            pdf_standards=list(job.standards),  # type: ignore[arg-type]
            timestamp=job.timestamp.astimezone(UTC),
        )
    except typst.TypstError as exc:
        raise _error(exc, "typst") from exc
    if not isinstance(out, bytes) or not out.startswith(b"%PDF"):
        raise OutputError("PDF rendering failed: typst returned no PDF")
    return out


def cli_argv(exe: str, root: Path, job: CompileJob, output: Path) -> list[str]:
    """The CLI command line: data stays in files, never in argv."""
    settings = {k: v for k, v in job.inputs.items() if k not in INPUT_FILES}
    argv = [
        exe,
        "compile",
        "--root",
        str(root),
        "--ignore-system-fonts",
        "--package-path",
        str(root / ".packages"),
        "--package-cache-path",
        str(root / ".packages"),
        "--creation-timestamp",
        str(int(job.timestamp.timestamp())),
        "--format",
        "pdf",
        "--input",
        "mode=files",
    ]
    for key, value in sorted(settings.items()):
        argv += ["--input", f"{key}={value}"]
    if job.standards:
        argv += ["--pdf-standard", ",".join(job.standards)]
    argv += [str(root / MAIN), str(output)]
    return argv


def compile_cli(exe: str, job: CompileJob) -> bytes:
    """Run the official Typst CLI on a private copy of the templates plus data files."""
    tmp = tempfile.mkdtemp(prefix="startup-sbom-pdf-")
    try:
        root = Path(tmp)
        for src in sorted(TEMPLATES.glob("*.typ")):
            shutil.copyfile(src, root / src.name)
        for key, name in INPUT_FILES.items():  # absent inputs are empty files
            (root / name).write_text(job.inputs.get(key, ""), encoding="utf-8")
        output = root / "out.pdf"
        env = {k: v for k, v in os.environ.items() if not k.startswith("TYPST_")}
        env["SOURCE_DATE_EPOCH"] = str(int(job.timestamp.timestamp()))
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, absolute executable from which()
                cli_argv(exe, root, job, output),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=CLI_TIMEOUT,
                check=False,
                env=env,
                cwd=root,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise _error(exc, "typst CLI") from exc
        if proc.returncode != 0:
            msg = clean(proc.stderr.decode("utf-8", "replace"), max_len=1500)
            raise OutputError(f"PDF rendering failed (typst CLI exit {proc.returncode}): {msg}")
        try:
            data = output.read_bytes()
        except OSError as exc:
            raise OutputError("PDF rendering failed: typst CLI wrote no output") from exc
        if not data.startswith(b"%PDF"):
            raise OutputError("PDF rendering failed: typst CLI output is not a PDF")
        return data
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
