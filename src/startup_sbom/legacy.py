"""Compatibility layer for the 1.x ``python3 main.py ...`` command line.

Old flags are translated to a 2.x scan.  Behaviour that was unsafe in 1.x (the
"chroot" mode bind-mounted the target over the host and executed target binaries
as root) is never reproduced: it maps to the safe static analysis with a notice.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from startup_sbom.context import ScanOptions
from startup_sbom.errors import StartupSBOMError


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Startup-SBOM 1.x compatibility wrapper (use `startup-sbom scan` instead).",
    )
    p.add_argument("--analysis-mode", default="static", choices=["static", "chroot"])
    p.add_argument("--static-type", default="info", choices=["info", "service"])
    p.add_argument("--volume-path", type=str)
    p.add_argument("--docker", type=str)
    p.add_argument("--save-file", type=str, default="")
    p.add_argument("--info-graphic", type=_bool, default=False)
    p.add_argument("--pkg-mgr", type=str, choices=["apt", "rpm", "pacman", "apk"])
    p.add_argument("--cve-analysis", action="store_true", default=False)
    return p


def run(argv: list[str] | None = None) -> int:
    """Translate 1.x arguments and run a 2.x scan; returns a process exit code."""
    from startup_sbom.pipeline import scan
    from startup_sbom.report import print_console, write_reports

    args = build_parser().parse_args(argv)
    err = Console(stderr=True)
    notice = "[legacy] main.py is deprecated; use `startup-sbom scan TARGET`."
    err.print(notice, markup=False)
    if args.analysis_mode == "chroot":
        err.print(
            "[legacy] chroot mode was removed (it mounted the target over the host and "
            "executed target binaries as root). Running safe static analysis instead; "
            "pass a `systemd-analyze plot` SVG via `startup-sbom scan --boot-timing`.",
            markup=False,
        )
    if args.pkg_mgr:
        err.print(
            "[legacy] --pkg-mgr ignored: every package database is auto-detected.", markup=False
        )

    target = f"docker:{args.docker}" if args.docker else f"dir:{args.volume_path or '/mnt'}"
    options = ScanOptions(
        offline=not args.cve_analysis,
        vuln_sources=("osv", "arch") if args.cve_analysis else (),
        epss=args.cve_analysis,
        kev=args.cve_analysis,
        eol=args.cve_analysis,
    )
    try:
        report = scan(target, options)
    except StartupSBOMError as exc:
        err.print(f"error: {exc}", markup=False, highlight=False)
        return 2
    print_console(report, Console())
    if args.save_file:
        base = Path(args.save_file)
        outputs = {"json": base, "cyclonedx": base.with_name(base.name + ".cdx.json")}
        if args.info_graphic:
            outputs["html"] = base.with_name(base.name + ".html")
        for path in write_reports(report, outputs):
            err.print(f"wrote {path}", markup=False, highlight=False)
    return 0


def main() -> None:
    sys.exit(run())
