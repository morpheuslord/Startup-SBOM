"""``startup-sbom intel`` commands: standalone CVE lookup and exploit-index refresh."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from startup_sbom.errors import StartupSBOMError
from startup_sbom.net import HttpClient

app = typer.Typer(
    help="Online intel for CVEs: advisories, exploit availability, PoCs and articles.",
    no_args_is_help=True,
)


def _cache_dir(value: Path | None) -> Path | None:
    if value is not None:
        return value
    env = os.environ.get("STARTUP_SBOM_CACHE_DIR")
    return Path(env) if env else None


CacheOpt = Annotated[
    Path | None, typer.Option("--cache-dir", help="Cache directory (default: user cache).")
]


@app.command("lookup")
def lookup_cmd(
    cves: Annotated[list[str], typer.Argument(help="One or more CVE ids.", metavar="CVE...")],
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")] = False,
    no_articles: Annotated[
        bool, typer.Option("--no-articles", help="Structured feeds only; fetch no web pages.")
    ] = False,
    refresh: Annotated[bool, typer.Option("--refresh", help="Revalidate cached data.")] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="No network access; cached intel only.")
    ] = False,
    cache_dir: CacheOpt = None,
) -> None:
    """Look up intel for CVE ids (third-party content is shown escaped and labelled)."""
    from startup_sbom.intel import ATTRIBUTIONS, lookup
    from startup_sbom.intel.render import print_bundle

    console = Console(highlight=False)
    bundles = []
    failed = False
    with HttpClient(offline=offline, cache_dir=_cache_dir(cache_dir)) as http:
        for cve in cves:
            try:
                bundles.append(lookup(cve, http, articles=not no_articles, refresh=refresh))
            except (ValueError, StartupSBOMError) as exc:
                typer.echo(f"error: {exc}", err=True)
                failed = True
    if as_json:
        doc = [b.model_dump(mode="json") for b in bundles]
        typer.echo(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        for bundle in bundles:
            print_bundle(bundle, console)
        if bundles:
            console.print("Sources: " + " ".join(ATTRIBUTIONS), style="dim", markup=False)
    if failed:
        raise typer.Exit(2)


@app.command("update-index")
def update_index_cmd(cache_dir: CacheOpt = None) -> None:
    """Refresh the compact Exploit-DB / Metasploit / nuclei index."""
    from startup_sbom.intel import update_index

    with HttpClient(cache_dir=_cache_dir(cache_dir)) as http:
        status = update_index(http)
    for key, value in status.items():
        typer.echo(f"{key}: {value}")
    if any(v.startswith("error") for v in status.values()):
        raise typer.Exit(1)
