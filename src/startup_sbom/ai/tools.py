"""Read-only, paged, size-capped report tools for the agents.

Every result is JSON wrapped in ``<untrusted_scan_data>`` with ``<`` and ``>``
escaped, so text from the scanned system cannot close the delimiter or forge
instructions.  There are no tools with side effects and no filesystem, network
or shell access.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from pydantic import Field

from startup_sbom.ai import INSTALL_HINT, AIUnavailableError
from startup_sbom.ai.index import ReportIndex, UnknownIdError

try:
    from pydantic_ai import ModelRetry, RunContext
    from pydantic_ai.toolsets import FunctionToolset
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the AI features need 'pydantic-ai': {INSTALL_HINT}") from exc

MAX_TOOL_CHARS = 12_000
OPEN_TAG = "<untrusted_scan_data"
CLOSE_TAG = "</untrusted_scan_data>"
_SOURCE_RE = re.compile(r"[^A-Za-z0-9_.:@/+-]")

Progress = Callable[[str], None]


@dataclass
class AgentDeps:
    """Run dependencies shared by every agent: the report index and a progress sink."""

    index: ReportIndex
    progress: Progress | None = None
    calls: list[str] = field(default_factory=list)  # tool-call trace (names only)
    delegations: list[dict[str, Any]] = field(default_factory=list)  # specialist results

    def note(self, message: str) -> None:
        self.calls.append(message)
        if self.progress is not None:
            self.progress(message)


def untrusted(payload: Any, *, source: str, max_chars: int = MAX_TOOL_CHARS) -> str:
    """Spotlight scanned data: escaped JSON inside an unforgeable delimiter, size-capped."""
    body = json.dumps(payload, default=str, ensure_ascii=False, separators=(",", ":"))
    body = body.replace("<", "\\u003c").replace(">", "\\u003e")
    if len(body) > max_chars:
        body = (
            body[:max_chars] + '..." [truncated: narrow the query with filters or page with offset]'
        )
    src = _SOURCE_RE.sub("_", source)[:120]
    return f'{OPEN_TAG} source="{src}">\n{body}\n{CLOSE_TAG}'


def _call(ctx: RunContext[AgentDeps], name: str, fn: Callable[[], Any], source: str) -> str:
    ctx.deps.note(f"tool {name}")
    try:
        return untrusted(fn(), source=source)
    except UnknownIdError as exc:
        raise ModelRetry(str(exc)) from None


SSVCValue = Literal["Act", "Attend", "Track*", "Track"]
Limit = Annotated[int, Field(ge=1, le=50)]
Offset = Annotated[int, Field(ge=0)]


def report_toolset() -> FunctionToolset[AgentDeps]:
    """A fresh toolset of read-only report tools (shared shape for every agent)."""
    ts: FunctionToolset[AgentDeps] = FunctionToolset()

    @ts.tool
    def get_summary(ctx: RunContext[AgentDeps]) -> str:
        """Scan target, OS, coverage gaps, headline counts and top risk drivers. Call first."""
        return _call(ctx, "get_summary", ctx.deps.index.summary, "summary")

    @ts.tool
    def list_threats(
        ctx: RunContext[AgentDeps],
        min_risk: Annotated[float, Field(ge=0, le=100)] = 0,
        ssvc: list[SSVCValue] | None = None,
        reachability: list[str] | None = None,
        network_exposed: bool | None = None,
        kev_only: bool = False,
        package: str | None = None,
        service: str | None = None,
        query: str | None = None,
        limit: Limit = 20,
        offset: Offset = 0,
    ) -> str:
        """Risk-ordered compact threat rows; filter and page, then use get_threat for detail."""
        return _call(
            ctx,
            "list_threats",
            lambda: ctx.deps.index.list_threats(
                min_risk=min_risk,
                ssvc=ssvc,
                reachability=reachability,
                network_exposed=network_exposed,
                kev_only=kev_only,
                package=package,
                service=service,
                query=query,
                limit=limit,
                offset=offset,
            ),
            "threats",
        )

    @ts.tool
    def get_threat(ctx: RunContext[AgentDeps], threat_id: str) -> str:
        """Full detail of one threat, its vulnerability records and explanation factors."""
        return _call(
            ctx, "get_threat", lambda: ctx.deps.index.get_threat(threat_id), f"threat:{threat_id}"
        )

    @ts.tool
    def explain_threat(ctx: RunContext[AgentDeps], threat_id: str) -> str:
        """Exact risk-score decomposition, SSVC decision trace and cited evidence of a threat."""
        return _call(
            ctx,
            "explain_threat",
            lambda: ctx.deps.index.explain_threat(threat_id),
            f"explain:{threat_id}",
        )

    @ts.tool
    def list_attack_chains(
        ctx: RunContext[AgentDeps],
        min_score: Annotated[float, Field(ge=0, le=100)] = 0,
        goal: str | None = None,
        include_mitigated: bool = True,
        limit: Limit = 10,
        offset: Offset = 0,
    ) -> str:
        """Attack chains (entry -> goal, score, likelihood), best first."""
        return _call(
            ctx,
            "list_attack_chains",
            lambda: ctx.deps.index.list_chains(
                min_score=min_score,
                goal=goal,
                include_mitigated=include_mitigated,
                limit=limit,
                offset=offset,
            ),
            "chains",
        )

    @ts.tool
    def get_attack_chain(ctx: RunContext[AgentDeps], chain_id: str) -> str:
        """One attack chain with every step (rule, states, technique, likelihood)."""
        return _call(
            ctx,
            "get_attack_chain",
            lambda: ctx.deps.index.get_chain(chain_id),
            f"chain:{chain_id}",
        )

    @ts.tool
    def get_blast_radius(
        ctx: RunContext[AgentDeps],
        package_id: str | None = None,
        limit: Limit = 10,
        offset: Offset = 0,
    ) -> str:
        """Which services/binaries load a package (one package, or the top entries)."""
        return _call(
            ctx,
            "get_blast_radius",
            lambda: ctx.deps.index.blast_radius(package_id, limit=limit, offset=offset),
            "blast",
        )

    @ts.tool
    def list_supply_chain_findings(
        ctx: RunContext[AgentDeps],
        kind: str | None = None,
        min_severity: Literal["critical", "high", "medium", "low"] | None = None,
        limit: Limit = 20,
        offset: Offset = 0,
    ) -> str:
        """Provenance / vendor-chain findings (third-party repos, unsigned, unmanaged)."""
        return _call(
            ctx,
            "list_supply_chain_findings",
            lambda: ctx.deps.index.list_supply_chain_findings(
                kind=kind, min_severity=min_severity, limit=limit, offset=offset
            ),
            "supply_chain",
        )

    @ts.tool
    def lookup_package(ctx: RunContext[AgentDeps], query: str) -> str:
        """Package detail by exact id (purl), or search by name to discover ids."""
        return _call(ctx, "lookup_package", lambda: ctx.deps.index.lookup_package(query), "package")

    @ts.tool
    def lookup_service(ctx: RunContext[AgentDeps], query: str) -> str:
        """Service detail by exact id (e.g. systemd:ssh.service), or search by name."""
        return _call(ctx, "lookup_service", lambda: ctx.deps.index.lookup_service(query), "service")

    @ts.tool
    def get_intel(ctx: RunContext[AgentDeps], cve: str) -> str:
        """Prefetched threat intel for a CVE in the report (exploits, KEV, EPSS trend, articles)."""
        return _call(ctx, "get_intel", lambda: ctx.deps.index.get_intel(cve), f"intel:{cve}")

    @ts.tool
    def get_fix_plan(ctx: RunContext[AgentDeps]) -> str:
        """Minimal fix set(s), single-fix what-ifs and the fix catalogue from the scanner."""
        return _call(ctx, "get_fix_plan", ctx.deps.index.fix_plan, "fix_plan")

    return ts


TOOL_NAMES = (
    "get_summary",
    "list_threats",
    "get_threat",
    "explain_threat",
    "list_attack_chains",
    "get_attack_chain",
    "get_blast_radius",
    "list_supply_chain_findings",
    "lookup_package",
    "lookup_service",
    "get_intel",
    "get_fix_plan",
)
