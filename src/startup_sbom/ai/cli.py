"""``startup-sbom ai``: analyze, agents, providers, mcp and serve subcommands.

Heavy imports (pydantic-ai, mcp, fasta2a) happen inside the commands, so ``--help``
and ``providers`` work without the optional extras and missing ones produce the
friendly :class:`~startup_sbom.ai.AIUnavailableError` hint instead of a traceback.
"""

from __future__ import annotations

import asyncio
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from startup_sbom.ai import AIError
from startup_sbom.ai.providers import PRICES, PRIORITY, PROVIDERS, available_providers
from startup_sbom.models import Report
from startup_sbom.textsafe import safe

app = typer.Typer(
    name="ai",
    help="Agentic AI analysis of scan reports, and MCP / A2A / ACP agent servers.",
    no_args_is_help=True,
    rich_markup_mode=None,
)

TOKEN_ENV = "STARTUP_SBOM_AGENT_TOKEN"  # noqa: S105 - env var name, not a secret
PLUGINS_ENV = "STARTUP_SBOM_AI_PLUGINS"
REMOTE_ENV = "STARTUP_SBOM_AI_AGENT_URLS"


class OutputFmt(StrEnum):
    json = "json"
    text = "text"
    markdown = "markdown"
    pdf = "pdf"


class Transport(StrEnum):
    stdio = "stdio"
    http = "http"


class ServeProtocol(StrEnum):
    a2a = "a2a"
    acp = "acp"
    both = "both"


def _fail(exc: Exception) -> typer.Exit:
    typer.echo(f"error: {safe(exc, 500)}", err=True)
    return typer.Exit(2)


def _load_report(path: Path) -> Report:
    try:
        return Report.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise _fail(exc) from exc


def _split(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _env_list(name: str) -> list[str]:
    return _split(os.environ.get(name))


def _progress(message: str) -> None:
    typer.echo(safe(message, 300), err=True)


@app.command()
def analyze(
    report_json: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    provider: Annotated[str | None, typer.Option(help="anthropic | openai | google | ...")] = None,
    model: Annotated[
        str | None, typer.Option(help="Exact model, e.g. anthropic:claude-haiku-4-5")
    ] = None,
    profile: Annotated[str, typer.Option(help="cheap | balanced | quality")] = "cheap",
    audience: Annotated[str, typer.Option(help="technical | executive")] = "technical",
    agents: Annotated[
        str | None, typer.Option(help="Comma-separated specialists, e.g. triage,remediation")
    ] = None,
    max_cost: Annotated[
        float, typer.Option(help="USD ceiling for the whole run (0 disables)")
    ] = 1.0,
    web_search: Annotated[
        bool | None,
        typer.Option(
            "--web-search/--no-web-search",
            help="DuckDuckGo context lookups (default: on for online scans; "
            "always off for offline scans).",
        ),
    ] = None,
    fmt: Annotated[OutputFmt, typer.Option("--format", "-f")] = OutputFmt.text,
    output: Annotated[Path | None, typer.Option("--output", "-o", dir_okay=False)] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No progress on stderr.")] = False,
) -> None:
    """Run the AI agents over a scan report and print or write the assessment."""
    report = _load_report(report_json)
    if fmt is OutputFmt.pdf and output is None:
        typer.echo("error: --format pdf needs --output FILE", err=True)
        raise typer.Exit(2)
    from startup_sbom.ai.orchestrator import analyze as run_analyze
    from startup_sbom.ai.outputs import render_assessment

    try:
        assessment = run_analyze(
            report,
            provider=provider,
            model=model,
            profile=profile,
            audience=audience,
            agents=_split(agents) or None,
            max_cost_usd=max_cost if max_cost > 0 else None,
            stream=None if quiet else _progress,
            web_search=web_search,
        )
        rendered = render_assessment(assessment, fmt.value, report=report)
    except AIError as exc:
        raise _fail(exc) from exc
    if output is not None:
        data = rendered if isinstance(rendered, bytes) else rendered.encode("utf-8")
        output.write_bytes(data)
        typer.echo(f"wrote {output} ({len(data)} bytes)", err=True)
    else:
        typer.echo(rendered if isinstance(rendered, str) else rendered.decode("utf-8", "replace"))
    if not assessment.grounding.passed:
        typer.echo(
            f"warning: {len(assessment.grounding.issues)} grounding issue(s) flagged",
            err=True,
        )


@app.command()
def agents(
    plugins: Annotated[
        str | None,
        typer.Option(help=f"Allow-listed entry-point names (default: ${PLUGINS_ENV})"),
    ] = None,
    remote: Annotated[
        list[str] | None,
        typer.Option("--remote", help="Remote A2A/ACP agent URL (repeatable)"),
    ] = None,
) -> None:
    """List the available specialists: built-ins, allow-listed plugins, remote agents."""
    from startup_sbom.ai.registry import build_registry

    try:
        registry = asyncio.run(
            build_registry(
                plugins=_split(plugins) or _env_list(PLUGINS_ENV),
                remote=remote or _env_list(REMOTE_ENV),
                token=os.environ.get(TOKEN_ENV) or None,
            )
        )
    except AIError as exc:
        raise _fail(exc) from exc
    for row in registry.describe():
        tags = f" [{', '.join(row['tags'])}]" if row["tags"] else ""
        typer.echo(
            f"{safe(row['name'], 48):<24} {safe(row['source'], 60):<28} "
            f"{safe(row['description'], 120)}{safe(tags, 80)}"
        )


@app.command()
def providers() -> None:
    """Show providers, their env keys, per-profile models, prices and configured state."""
    configured = available_providers()
    for name in PRIORITY:
        info = PROVIDERS[name]
        state = "configured" if configured[name] else f"set {' or '.join(info.env)}"
        typer.echo(f"{name}  ({state})")
        for tier in ("cheap", "balanced", "quality"):
            model = info.profiles[tier]
            price = PRICES.get(model)
            if price is None:
                cost = "price unknown"
            else:
                mark = "" if price.verified else " (unverified)"
                cost = f"${price.input:g}/${price.output:g} per MTok{mark}"
            typer.echo(f"  {tier:<9} {model:<40} {cost}")
        if info.note:
            typer.echo(f"  note: {info.note}")


@app.command()
def mcp(
    report: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, help="Report JSON to serve.")
    ] = None,
    transport: Annotated[Transport, typer.Option()] = Transport.stdio,
    host: Annotated[str, typer.Option(help="HTTP bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8765,
    allow_scan: Annotated[
        list[Path] | None,
        typer.Option("--allow-scan", help="Enable scan_target under this root (repeatable)."),
    ] = None,
) -> None:
    """Serve report tools over MCP (stdio by default, or streamable HTTP)."""
    from startup_sbom.ai.mcp_server import build_server, run_server

    loaded = _load_report(report) if report else None
    if loaded is None and not allow_scan:
        typer.echo("error: pass --report FILE and/or --allow-scan PREFIX", err=True)
        raise typer.Exit(2)
    server = build_server(loaded, allow_scan=tuple(allow_scan or ()))
    if transport is Transport.http:
        typer.echo(f"MCP streamable HTTP on http://{host}:{port}/mcp", err=True)
    run_server(server, transport=transport.value, host=host, port=port)


@app.command()
def serve(
    report: Annotated[
        Path, typer.Option(exists=True, dir_okay=False, help="Report JSON to serve.")
    ],
    protocol: Annotated[ServeProtocol, typer.Option()] = ServeProtocol.a2a,
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8770,
    provider: Annotated[str | None, typer.Option()] = None,
    model: Annotated[str | None, typer.Option()] = None,
    profile: Annotated[str, typer.Option()] = "cheap",
    agents: Annotated[str | None, typer.Option(help="Only serve these specialists.")] = None,
) -> None:
    """Serve the orchestrator and specialists over A2A 1.0 and/or the ACP REST facade."""
    import uvicorn

    from startup_sbom.ai.acp import build_acp_app, require_token
    from startup_sbom.ai.orchestrator import ModelSet
    from startup_sbom.ai.providers import resolve
    from startup_sbom.ai.registry import build_registry

    token = os.environ.get(TOKEN_ENV) or None
    try:
        require_token(host, token)
        loaded = _load_report(report)
        choice = resolve(provider=provider, model=model, profile=profile)
        models = ModelSet.from_choice(choice)
        registry = asyncio.run(
            build_registry(
                plugins=_env_list(PLUGINS_ENV),
                remote=_env_list(REMOTE_ENV),
                token=token,
            )
        )
        if agents:
            registry = registry.select(_split(agents))
        if protocol is ServeProtocol.acp:
            served = build_acp_app(loaded, models=models, registry=registry, token=token)
        else:
            from starlette.routing import Mount

            from startup_sbom.ai.a2a import build_a2a_app

            extra = []
            if protocol is ServeProtocol.both:
                acp_inner = build_acp_app(loaded, models=models, registry=registry)
                extra = [Mount("/acp", app=acp_inner)]
            served = build_a2a_app(
                loaded,
                models=models,
                registry=registry,
                base_url=f"http://{host}:{port}",
                token=token,
                extra_routes=extra,
            )
    except AIError as exc:
        raise _fail(exc) from exc
    names = ", ".join(registry.names())
    typer.echo(
        f"serving {protocol.value} on http://{host}:{port} (agents: {safe(names, 300)})",
        err=True,
    )
    uvicorn.run(served, host=host, port=port, log_level="warning")


def main() -> None:  # pragma: no cover - thin console entry
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
