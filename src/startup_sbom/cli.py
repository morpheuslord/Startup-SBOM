"""Command-line interface (``startup-sbom``)."""

from __future__ import annotations

import logging
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from typer.exceptions import TyperException

from startup_sbom import __version__
from startup_sbom.context import ScanOptions
from startup_sbom.errors import StartupSBOMError, TargetError
from startup_sbom.log import configure_logging
from startup_sbom.models import Report, Severity, SSVCDecision, VulnStatus

log = logging.getLogger("startup_sbom")

EXIT_OK = 0
EXIT_POLICY = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

app = typer.Typer(
    name="startup-sbom",
    help=(
        "Map what a Linux system or container runs at boot to the packages behind it, "
        "reverse vulnerabilities into concrete threats, chain attacks and trace "
        "supply-chain blast radius.  Read-only: nothing in the target is executed, "
        "mounted or modified."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
db_app = typer.Typer(help="Manage cached vulnerability intelligence (KEV, EPSS, OSV).")
app.add_typer(db_app, name="db")


class Format(StrEnum):
    json = "json"
    cyclonedx = "cyclonedx"
    spdx = "spdx"
    sarif = "sarif"
    openvex = "openvex"
    cdx_vex = "cdx-vex"
    markdown = "markdown"
    html = "html"
    dot = "dot"
    mermaid = "mermaid"
    pdf = "pdf"


class FailOn(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    attend = "attend"
    act = "act"


class CdxSpec(StrEnum):
    v15 = "1.5"
    v16 = "1.6"
    v17 = "1.7"


def _cache_dir() -> Path | None:
    value = os.environ.get("STARTUP_SBOM_CACHE_DIR")
    return Path(value) if value else None


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help=(
                "What to analyse: dir:PATH, host:, tar:FILE, docker-archive:FILE, "
                "oci-dir:DIR, oci-archive:FILE, docker:NAME, podman:NAME, nerdctl:NAME. "
                "A bare existing path is auto-detected."
            ),
        ),
    ],
    formats: Annotated[
        list[Format] | None,
        typer.Option("--format", "-f", help="Report format to write (repeatable)."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output directory (default ./startup-sbom-out), or '-' for stdout.",
        ),
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="No network access; use cached data only.")
    ] = False,
    platform: Annotated[
        str | None, typer.Option("--platform", help="Image platform, e.g. linux/arm64.")
    ] = None,
    sources: Annotated[
        str, typer.Option("--sources", help="Vulnerability sources: osv,arch,nvd or 'none'.")
    ] = "osv,arch",
    no_epss: Annotated[bool, typer.Option("--no-epss", help="Skip EPSS enrichment.")] = False,
    no_kev: Annotated[bool, typer.Option("--no-kev", help="Skip CISA KEV enrichment.")] = False,
    no_eol: Annotated[bool, typer.Option("--no-eol", help="Skip end-of-life lookup.")] = False,
    no_language_packages: Annotated[
        bool, typer.Option("--no-language-packages", help="Skip Python/npm/Go/Java/Rust.")
    ] = False,
    no_link_analysis: Annotated[
        bool, typer.Option("--no-link-analysis", help="Skip ELF library reachability.")
    ] = False,
    integrity: Annotated[
        bool, typer.Option("--integrity", help="Verify file digests against package DBs.")
    ] = False,
    boot_timing: Annotated[
        Path | None,
        typer.Option(
            "--boot-timing",
            help="`systemd-analyze plot` SVG or `blame` output captured on the target.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    prefetch_intel: Annotated[
        bool,
        typer.Option(
            "--prefetch-intel",
            help="Fetch advisories, exploit availability and write-ups for top findings.",
        ),
    ] = False,
    intel_max_cves: Annotated[
        int, typer.Option("--intel-max-cves", min=1, max=500, help="CVEs to prefetch.")
    ] = 25,
    intel_max_articles: Annotated[
        int, typer.Option("--intel-max-articles", min=0, max=20, help="Articles per CVE.")
    ] = 4,
    intel_budget: Annotated[
        float, typer.Option("--intel-budget", min=10.0, help="Prefetch time budget (seconds).")
    ] = 120.0,
    no_intel_articles: Annotated[
        bool,
        typer.Option("--no-intel-articles", help="Structured intel sources only, no articles."),
    ] = False,
    cdx_spec: Annotated[
        CdxSpec, typer.Option("--cdx-spec", help="CycloneDX spec version.")
    ] = CdxSpec.v16,
    vex_unreachable_not_affected: Annotated[
        bool,
        typer.Option(
            "--vex-unreachable-not-affected",
            help=(
                "Mark vulns with no execution path as not_affected in VEX "
                "(default: under_investigation)."
            ),
        ),
    ] = False,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Exit 1 when findings reach this level.")
    ] = FailOn.none,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No console summary.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="More detail.")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Debug logging and tracebacks.")] = False,
) -> None:
    """Scan a root filesystem, image or container."""
    from startup_sbom.pipeline import scan as run_scan
    from startup_sbom.report import FORMATS, RenderOptions, print_console, render, write_reports

    configure_logging(verbose=verbose, debug=debug, quiet=quiet)
    chosen = list(dict.fromkeys(formats or []))
    if output == "-" and len(chosen) != 1:
        raise typer.BadParameter("'-o -' requires exactly one --format", param_hint="--output")

    vuln_sources = tuple(
        s for s in (x.strip().lower() for x in sources.split(",")) if s and s != "none"
    )
    unknown = set(vuln_sources) - {"osv", "arch", "nvd"}
    if unknown:
        raise typer.BadParameter(f"unknown source(s): {', '.join(sorted(unknown))}")
    options = ScanOptions(
        offline=offline,
        vuln_sources=vuln_sources,
        nvd_api_key=os.environ.get("NVD_API_KEY") or None,
        epss=not no_epss,
        kev=not no_kev,
        eol=not no_eol,
        cache_dir=_cache_dir(),
        language_packages=not no_language_packages,
        link_analysis=not no_link_analysis,
        integrity_check=integrity,
        platform=platform,
        boot_timing_file=boot_timing,
        vex_not_affected_unreachable=vex_unreachable_not_affected,
        prefetch_intel=prefetch_intel,
        intel_max_cves=intel_max_cves,
        intel_max_articles=intel_max_articles,
        intel_budget=intel_budget,
        intel_articles=not no_intel_articles,
    )
    missing = [f.value for f in chosen if f.value not in _available_formats()]
    if missing:
        raise typer.BadParameter(
            f"format(s) not available in this installation: {', '.join(missing)}"
        )
    err = Console(stderr=True)
    show_progress = not quiet and err.is_terminal
    if show_progress:
        with err.status("Scanning…") as status:
            report = run_scan(
                target,
                options,
                progress=lambda e: status.update(f"[{e.index}/{e.total}] {e.stage}…"),
                strict=debug,
            )
    else:
        report = run_scan(target, options, strict=debug)

    render_opts = RenderOptions(
        cdx_spec=cdx_spec.value, vex_not_affected_unreachable=vex_unreachable_not_affected
    )
    if output == "-":
        if chosen[0] is Format.pdf:
            from startup_sbom.report import render_bytes

            sys.stdout.buffer.write(render_bytes(report, "pdf", render_opts))
            sys.stdout.buffer.flush()
        else:
            sys.stdout.write(render(report, chosen[0].value, render_opts))
            sys.stdout.flush()
    else:
        if not quiet:
            print_console(report, Console(), verbose=verbose)
        if chosen:
            out_dir = Path(output or "startup-sbom-out")
            outputs = {f.value: out_dir / FORMATS[f.value].default_filename for f in chosen}
            written = write_reports(report, outputs, render_opts)
            if not quiet:
                for path in written:
                    err.print(f"wrote {path}", markup=False, highlight=False)

    if policy_violated(report, fail_on):
        raise typer.Exit(EXIT_POLICY)


def policy_violated(report: Report, fail_on: FailOn | str) -> bool:
    """Whether ``report`` reaches the ``--fail-on`` threshold."""
    level = FailOn(fail_on)
    if level is FailOn.none:
        return False
    if level in (FailOn.attend, FailOn.act):
        wanted = {SSVCDecision.ACT}
        if level is FailOn.attend:
            wanted.add(SSVCDecision.ATTEND)
        return any(t.ssvc is not None and t.ssvc.decision in wanted for t in report.threats)
    threshold = Severity(level.value).rank
    active = (VulnStatus.AFFECTED, VulnStatus.NO_FIX_AVAILABLE, VulnStatus.UNDER_INVESTIGATION)
    return any(v.severity.rank >= threshold for v in report.vulnerabilities if v.status in active)


@db_app.command("update")
def db_update() -> None:
    """Download/refresh KEV and EPSS feeds into the local cache."""
    from startup_sbom.net import HttpClient
    from startup_sbom.vulns import update_feeds

    configure_logging()
    with HttpClient(cache_dir=_cache_dir()) as http:
        for name, state in sorted(update_feeds(http).items()):
            typer.echo(f"{name}: {state}")


@db_app.command("status")
def db_status() -> None:
    """Show cache location and feed freshness."""
    from startup_sbom.net import HttpClient, default_cache_dir
    from startup_sbom.vulns import feed_status

    configure_logging()
    with HttpClient(offline=True, cache_dir=_cache_dir()) as http:
        typer.echo(f"cache: {_cache_dir() or default_cache_dir()}")
        for name, state in sorted(feed_status(http).items()):
            typer.echo(f"{name}: {state}")


@db_app.command("clear")
def db_clear() -> None:
    """Delete the HTTP cache."""
    import shutil

    from startup_sbom.net import default_cache_dir

    target = (_cache_dir() or default_cache_dir()) / "http"
    if target.is_dir():
        shutil.rmtree(target)
    typer.echo(f"cleared {target}")


@app.command()
def schema() -> None:
    """Print the JSON Schema of the native report."""
    from startup_sbom.report import json_schema

    sys.stdout.write(json_schema() + "\n")


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"startup-sbom {__version__}")


def _available_formats() -> set[str]:
    from startup_sbom.report import FORMATS

    return set(FORMATS)


@app.command()
def tui(
    report: Annotated[
        Path | None,
        typer.Option("--report", help="Open an existing report.json instead of scanning."),
    ] = None,
    target: Annotated[str | None, typer.Argument(help="Pre-select a scan target.")] = None,
) -> None:
    """Interactive terminal UI for scanning and browsing results."""
    try:
        from startup_sbom.tui import run as run_tui
    except ImportError as exc:  # pragma: no cover - optional extra
        Console(stderr=True).print(
            "the TUI needs the optional extra: pip install 'startup-sbom[tui]'",
            markup=False,
        )
        raise typer.Exit(EXIT_USAGE) from exc
    run_tui(report_path=report, target=target)


def _mount_optional_apps() -> None:
    """Attach subsystem CLIs that may still be absent in partial installs."""
    try:
        from startup_sbom.intel.cli import app as intel_app
    except ImportError:  # pragma: no cover
        pass
    else:
        app.add_typer(intel_app, name="intel", help="Look up and cache CVE intelligence.")
    try:
        from startup_sbom.ai.cli import app as ai_app
    except ImportError:  # pragma: no cover
        pass
    else:
        app.add_typer(ai_app, name="ai", help="AI analysis, MCP and agent servers.")


_mount_optional_apps()


def main() -> None:
    """Console-script entry point with stable exit codes."""
    try:
        app(standalone_mode=False)
    except typer.Exit as exc:
        sys.exit(exc.exit_code)
    except (typer.Abort, KeyboardInterrupt):
        Console(stderr=True).print("aborted", markup=False)
        sys.exit(130)
    except TargetError as exc:
        Console(stderr=True).print(f"error: {exc}", markup=False, highlight=False)
        sys.exit(EXIT_USAGE)
    except StartupSBOMError as exc:
        Console(stderr=True).print(f"error: {exc}", markup=False, highlight=False)
        sys.exit(EXIT_INTERNAL)
    except TyperException as exc:  # usage errors from Typer's bundled click
        show = getattr(exc, "show", None)
        if callable(show):
            show()
        else:
            Console(stderr=True).print(f"error: {exc}", markup=False, highlight=False)
        sys.exit(EXIT_USAGE)
    except Exception as exc:
        if log.isEnabledFor(logging.DEBUG):
            raise
        Console(stderr=True).print(
            f"internal error: {type(exc).__name__}: {exc} (re-run with --debug)",
            markup=False,
            highlight=False,
        )
        sys.exit(EXIT_INTERNAL)
    sys.exit(EXIT_OK)
