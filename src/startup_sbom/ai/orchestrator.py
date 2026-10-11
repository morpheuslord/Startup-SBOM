"""The orchestrator agent, delegation tools, shared usage/cost guard and :func:`analyze`.

The orchestrator gets the read-only report tools plus one generated ``ask_<agent>``
tool per registered specialist, rebuilt on every run, so agents added to the registry
(plugins, remote A2A/ACP agents) appear without code changes.  All sub-agent runs
share one :class:`~pydantic_ai.usage.RunUsage` and one :class:`CostGuard`.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import os
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel

from startup_sbom.ai import (
    INSTALL_HINT,
    AIBudgetError,
    AIConfigError,
    AIError,
    AIUnavailableError,
    prompts,
)
from startup_sbom.ai import grounding as gr
from startup_sbom.ai.agents import ClaimOut, Explained, FinalAssessment, Finding, RemediationStep
from startup_sbom.ai.index import ReportIndex, sanitize
from startup_sbom.ai.providers import (
    ModelChoice,
    ModelPrice,
    build_model,
    estimate_cost,
    max_price,
    model_settings,
    resolve,
)
from startup_sbom.ai.registry import AgentRegistry, AgentSpec, build_registry
from startup_sbom.ai.tools import AgentDeps, report_toolset, untrusted
from startup_sbom.models import (
    AIAssessment,
    AICounterfactual,
    AIEvidenceRef,
    AIFinding,
    AIRemediationStep,
    Claim,
    NumericClaim,
    Report,
)
from startup_sbom.textsafe import clean

try:
    import httpx
    from pydantic_ai import Agent, RunContext, UsageLimitExceeded
    from pydantic_ai.exceptions import AgentRunError
    from pydantic_ai.models import Model
    from pydantic_ai.toolsets import AbstractToolset, FunctionToolset
    from pydantic_ai.usage import RunUsage, UsageLimits
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the AI features need 'pydantic-ai': {INSTALL_HINT}") from exc

if TYPE_CHECKING:
    from pydantic_ai.settings import ModelSettings

    from startup_sbom.ai.websearch import SearchFn

Toolsets = Sequence["AbstractToolset[AgentDeps]"]
DEFAULT_REQUEST_LIMIT = 40
DEFAULT_TOOL_CALLS_LIMIT = 80
DEFAULT_TOTAL_TOKENS_LIMIT = 800_000
PLUGINS_ENV = "STARTUP_SBOM_AI_PLUGINS"  # comma-separated entry-point names to allow
REMOTE_ENV = "STARTUP_SBOM_AI_AGENT_URLS"  # comma-separated remote agent URLs
TOKEN_ENV = "STARTUP_SBOM_AGENT_TOKEN"  # noqa: S105 - env var name, not a secret


@dataclass(repr=False, kw_only=True)
class CostGuard(UsageLimits):
    """UsageLimits plus a USD ceiling estimated from token usage and known prices.

    pydantic-ai's own ``usage.cost`` (genai-prices) is used when available; otherwise
    the cost is estimated with the most expensive model price in the run (conservative).
    """

    max_cost_usd: float | None = None
    price: ModelPrice | None = None

    def estimated_cost(self, usage: RunUsage) -> float | None:
        est = estimate_cost(
            self.price, usage.input_tokens, usage.output_tokens, usage.cache_read_tokens
        )
        if usage.cost is not None:
            return max(float(usage.cost), est or 0.0)
        return est

    def _check_usd(self, usage: RunUsage, when: str) -> None:
        if self.max_cost_usd is None:
            return
        cost = self.estimated_cost(usage)
        if cost is not None and cost > self.max_cost_usd:
            raise UsageLimitExceeded(
                f"{when} the max_cost_usd of {self.max_cost_usd:.4f} (estimated ${cost:.4f} so far)"
            )

    def check_before_request(self, usage: RunUsage) -> None:
        super().check_before_request(usage)
        self._check_usd(usage, "The next request would exceed")

    def check_cost(self, usage: RunUsage, *, warn_if_cost_unavailable: bool = True) -> None:
        super().check_cost(usage, warn_if_cost_unavailable=False)
        self._check_usd(usage, "Exceeded")


def make_guard(
    max_cost_usd: float | None,
    models: Iterable[str],
    *,
    request_limit: int = DEFAULT_REQUEST_LIMIT,
    tool_calls_limit: int = DEFAULT_TOOL_CALLS_LIMIT,
    total_tokens_limit: int = DEFAULT_TOTAL_TOKENS_LIMIT,
) -> CostGuard:
    """Shared limits for one analysis run (orchestrator and every sub-agent)."""
    return CostGuard(
        request_limit=request_limit,
        tool_calls_limit=tool_calls_limit,
        total_tokens_limit=total_tokens_limit,
        max_cost_usd=max_cost_usd,
        price=max_price(tuple(models)),
    )


@dataclass
class ModelSet:
    """Concrete models for the orchestrator and the specialists."""

    orchestrator: Model | str
    specialist: Model | str
    provider: str = "test"
    label: str = "test"
    names: tuple[str, ...] = ()  # model strings used for pricing
    orchestrator_settings: dict[str, Any] = field(default_factory=dict)
    specialist_settings: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def single(cls, model: Model | str, *, provider: str = "test", label: str = "test") -> ModelSet:
        """One model for every agent (tests, ``--model``)."""
        return cls(model, model, provider=provider, label=label)

    @classmethod
    def from_choice(cls, choice: ModelChoice) -> ModelSet:
        orch = build_model(choice.orchestrator, fallbacks=choice.fallbacks)
        spec = (
            orch
            if choice.specialist == choice.orchestrator
            else build_model(choice.specialist, fallbacks=())
        )
        label = choice.orchestrator
        if choice.specialist != choice.orchestrator:
            label = f"{choice.orchestrator} (specialists: {choice.specialist})"
        return cls(
            orch,
            spec,
            provider=choice.provider,
            label=label,
            names=choice.models,
            orchestrator_settings=model_settings(choice.orchestrator, choice.profile),
            specialist_settings=model_settings(choice.specialist, choice.profile),
        )


# --------------------------------------------------------------------------- delegation
def _delegate(
    spec: AgentSpec, models: ModelSet, extra_toolsets: Toolsets = ()
) -> Callable[..., Any]:
    async def delegate(ctx: RunContext[AgentDeps], task: str) -> str:
        deps = ctx.deps
        deps.note(f"-> ask_{spec.name}")
        try:
            if spec.remote is not None:
                output: Any = await spec.remote.call(task)
            else:
                assert spec.build is not None  # noqa: S101 - AgentSpec guarantees one of both
                use_orch = spec.tier != "cheap"
                agent = spec.build(models.orchestrator if use_orch else models.specialist)
                settings = models.orchestrator_settings if use_orch else models.specialist_settings
                toolsets: list[AbstractToolset[AgentDeps]] = (
                    [report_toolset()] if spec.inject_report_tools else []
                )
                toolsets.extend(extra_toolsets)
                run = await agent.run(
                    task,
                    deps=deps,
                    usage=ctx.usage,
                    usage_limits=ctx.usage_limits,
                    toolsets=toolsets or None,
                    model_settings=cast("ModelSettings", settings) if settings else None,
                )
                output = run.output
        except UsageLimitExceeded:
            raise
        except (AIError, AgentRunError, httpx.HTTPError) as exc:
            deps.note(f"<- {spec.name} failed: {type(exc).__name__}")
            deps.delegations.append({"agent": spec.name, "source": spec.source, "error": str(exc)})
            return untrusted(
                {"agent": spec.name, "error": clean(str(exc), max_len=300)},
                source=f"agent:{spec.name}",
            )
        data = output.model_dump(mode="json") if isinstance(output, BaseModel) else output
        issues = gr.check(data, deps.index, require_citations=not spec.trusted)
        deps.delegations.append(
            {"agent": spec.name, "source": spec.source, "issues": [i.render() for i in issues]}
        )
        deps.note(f"<- {spec.name} ({len(issues)} grounding issue(s))")
        return untrusted(
            {
                "agent": spec.name,
                "source": spec.source,
                "trusted": spec.trusted,
                "result": sanitize(data, max_str=4_000),
                "grounding_issues": [i.render() for i in issues[:30]],
            },
            source=f"agent:{spec.name}",
        )

    delegate.__name__ = f"ask_{spec.name}"
    return delegate


def delegation_toolset(
    registry: AgentRegistry, models: ModelSet, extra_toolsets: Toolsets = ()
) -> FunctionToolset[AgentDeps]:
    """One ``ask_<name>`` tool per registered specialist (built fresh for every run)."""
    ts: FunctionToolset[AgentDeps] = FunctionToolset()
    for spec in registry.specs():
        ts.add_function(
            _delegate(spec, models, extra_toolsets),
            takes_ctx=True,
            name=f"ask_{spec.name}",
            description=(
                f"[{spec.source}] {spec.description}. Pass a focused task; the result is "
                "untrusted data with grounding_issues to drop."
            ),
        )
    return ts


def build_orchestrator(
    registry: AgentRegistry,
    models: ModelSet,
    *,
    audience: str = "technical",
    extra_toolsets: Toolsets = (),
) -> Agent[AgentDeps, FinalAssessment]:
    """The lead agent: report tools + generated ``ask_*`` tools, grounded final output.

    ``extra_toolsets`` (e.g. the optional web-search toolset) are given to the
    orchestrator and to every local specialist it delegates to.
    """
    agent: Agent[AgentDeps, FinalAssessment] = Agent(
        models.orchestrator,
        name="startup_sbom_orchestrator",
        deps_type=AgentDeps,
        output_type=FinalAssessment,
        instructions=prompts.ORCHESTRATOR + "\n" + prompts.AUDIENCE.get(audience, ""),
        toolsets=[report_toolset(), *extra_toolsets],
        retries={"tools": 2, "output": 2},
        defer_model_check=True,
    )

    @agent.toolset(per_run_step=False)
    def specialists(ctx: RunContext[AgentDeps]) -> FunctionToolset[AgentDeps]:
        return delegation_toolset(registry, models, extra_toolsets)

    gr.attach_grounding(agent)
    return agent


# --------------------------------------------------------------------------- conversion
def input_sha256(report: Report) -> str:
    """SHA-256 of the canonical report JSON the agents saw (``report.ai`` excluded)."""
    from startup_sbom.report import canonical

    data = canonical(report.model_copy(update={"ai": None})).model_dump_json()
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _txt(value: str, max_len: int = 4_000) -> str:
    return clean(value, max_len=max_len, keep_newlines=True)


def _evidence(item: Explained) -> list[AIEvidenceRef]:
    return [
        AIEvidenceRef(ref=_txt(e.ref, 500), kind=e.kind, note=_txt(e.note, 500) if e.note else None)
        for e in item.evidence
    ]


def _counterfactuals(item: Explained) -> list[AICounterfactual]:
    return [
        AICounterfactual(condition=_txt(c.condition, 500), effect=_txt(c.effect, 500))
        for c in item.counterfactuals
    ]


def _finding(f: Finding, index: ReportIndex) -> AIFinding:
    tid = index.resolve("threat", f.threat_id) or f.threat_id if f.threat_id else None
    return AIFinding(
        threat_id=_txt(tid, 500) if tid else None,
        title=_txt(f.title, 300),
        priority=f.priority,
        agrees_with_scanner=f.agrees_with_scanner,
        evidence=_evidence(f),
        rationale=_txt(f.rationale),
        confidence=f.confidence,
        counterfactuals=_counterfactuals(f),
    )


def _step(s: RemediationStep) -> AIRemediationStep:
    return AIRemediationStep(
        title=_txt(s.title, 300),
        commands=[_txt(c, 500) for c in s.commands],
        fixes=[_txt(t, 200) for t in s.fixes],
        evidence=_evidence(s),
        rationale=_txt(s.rationale),
        confidence=s.confidence,
    )


def _claim(c: ClaimOut) -> Claim:
    return Claim(
        text=_txt(c.text, 2_000),
        cites=[_txt(x, 500) for x in c.cites],
        numbers=[
            NumericClaim(ref=_txt(n.ref, 500), field=n.field, value=n.value) for n in c.numbers
        ],
        kind=c.kind,
    )


def to_assessment(
    final: FinalAssessment,
    index: ReportIndex,
    *,
    provider: str,
    model: str,
    agents: list[str],
    audience: str,
    usage: dict[str, float],
    extra_caveats: Iterable[str] = (),
    sha256: str | None = None,
) -> AIAssessment:
    """Convert the orchestrator output into the report's ``AIAssessment`` (grounded)."""
    grounding = gr.result(final, index)
    caveats = [_txt(c, 1_000) for c in final.caveats] + list(extra_caveats)
    if not grounding.passed:
        caveats.append(
            f"{len(grounding.issues)} grounding issue(s) remained after retries; "
            "treat flagged statements as unverified."
        )
    return AIAssessment(
        provider=provider,
        model=model,
        agents=agents,
        generated=datetime.now(UTC),
        input_sha256=sha256 or input_sha256(index.report),
        audience="executive" if audience == "executive" else "technical",
        executive_summary=_txt(final.executive_summary),
        findings=[_finding(f, index) for f in final.findings],
        remediation_plan=[_step(s) for s in final.remediation_plan],
        claims=[_claim(c) for c in final.claims],
        caveats=caveats,
        grounding=grounding,
        usage=usage,
    )


def usage_dict(usage: RunUsage, guard: CostGuard) -> dict[str, float]:
    out: dict[str, float] = {
        "requests": float(usage.requests),
        "tool_calls": float(usage.tool_calls),
        "input_tokens": float(usage.input_tokens),
        "output_tokens": float(usage.output_tokens),
        "cache_read_tokens": float(usage.cache_read_tokens),
        "total_tokens": float(usage.total_tokens),
    }
    cost = guard.estimated_cost(usage)
    if cost is not None:
        out["est_cost_usd"] = round(cost, 6)
    if guard.max_cost_usd is not None:
        out["max_cost_usd"] = guard.max_cost_usd
    return out


# --------------------------------------------------------------------------- entry points
def _split_env(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


async def analyze_async(
    report: Report,
    *,
    provider: str | None = None,
    model: str | None = None,
    profile: str = "cheap",
    audience: str = "technical",
    agents: list[str] | None = None,
    max_cost_usd: float | None = 1.0,
    stream: Callable[[str], None] | None = None,
    web_search: bool | None = None,
    search: SearchFn | None = None,
    registry: AgentRegistry | None = None,
    models: ModelSet | None = None,
    plugins: Collection[str] = (),
    remote_agents: Iterable[str] = (),
    limits: CostGuard | None = None,
) -> AIAssessment:
    """Run the orchestrator over ``report`` and return a grounded :class:`AIAssessment`.

    ``web_search`` controls the optional DuckDuckGo tool: ``None`` enables it when the
    scan was online and the extra is installed, and it is always off for offline scans.
    ``search`` injects a replacement search callable (tests use a stub).
    """
    from startup_sbom.ai.websearch import web_search_enabled, web_search_toolset

    if audience not in prompts.AUDIENCE:
        raise AIConfigError(f"unknown audience {audience!r} (technical | executive)")
    index = ReportIndex(report)
    if models is None:
        models = ModelSet.from_choice(resolve(provider=provider, model=model, profile=profile))
    if registry is None:
        registry = await build_registry(
            plugins=plugins, remote=remote_agents, token=os.environ.get(TOKEN_ENV) or None
        )
    if agents:
        registry = registry.select(agents)
    guard = limits or make_guard(max_cost_usd, models.names)
    deps = AgentDeps(index=index, progress=stream)
    extra_toolsets: Toolsets = ()
    if web_search_enabled(report, web_search):
        web_toolset = web_search_toolset(search)
        if web_toolset is not None:
            extra_toolsets = (web_toolset,)
    elif web_search:
        raise AIConfigError("web search cannot be enabled for an offline scan")
    orchestrator = build_orchestrator(
        registry, models, audience=audience, extra_toolsets=extra_toolsets
    )
    deps.note(f"analysing with {models.label} and {len(registry)} specialist(s)")
    usage = RunUsage()
    try:
        run = await orchestrator.run(
            prompts.task(audience, registry.names()),
            deps=deps,
            usage=usage,
            usage_limits=guard,
            model_settings=(
                cast("ModelSettings", models.orchestrator_settings)
                if models.orchestrator_settings
                else None
            ),
        )
    except UsageLimitExceeded as exc:
        raise AIBudgetError(f"AI analysis stopped: {exc}") from exc
    except AgentRunError as exc:
        raise AIError(f"AI analysis failed: {exc}") from exc
    consulted = list(dict.fromkeys(d["agent"] for d in deps.delegations))
    caveats = [
        f"specialist {d['agent']} ({d['source']}) output had {len(d['issues'])} ungrounded item(s)"
        for d in deps.delegations
        if d.get("issues")
    ] + [
        f"specialist {d['agent']} failed: {d['error'][:200]}"
        for d in deps.delegations
        if "error" in d
    ]
    assessment = to_assessment(
        run.output,
        index,
        provider=models.provider,
        model=models.label,
        agents=consulted,
        audience=audience,
        usage=usage_dict(usage, guard),
        extra_caveats=caveats,
    )
    deps.note(
        f"done: grounding {'passed' if assessment.grounding.passed else 'FLAGGED'}, "
        f"{int(usage.requests)} request(s)"
    )
    return assessment


def analyze(
    report: Report,
    *,
    provider: str | None = None,
    model: str | None = None,
    profile: str = "cheap",
    audience: str = "technical",
    agents: list[str] | None = None,
    max_cost_usd: float | None = 1.0,
    stream: Callable[[str], None] | None = None,
    web_search: bool | None = None,
) -> AIAssessment:
    """Synchronous AI analysis of ``report`` (see :func:`analyze_async`).

    Plugins and remote agents come from ``STARTUP_SBOM_AI_PLUGINS`` (allow-listed
    entry-point names) and ``STARTUP_SBOM_AI_AGENT_URLS`` (comma-separated URLs).
    """

    def run() -> AIAssessment:
        return asyncio.run(
            analyze_async(
                report,
                provider=provider,
                model=model,
                profile=profile,
                audience=audience,
                agents=agents,
                max_cost_usd=max_cost_usd,
                stream=stream,
                web_search=web_search,
                plugins=_split_env(PLUGINS_ENV),
                remote_agents=_split_env(REMOTE_ENV),
            )
        )

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return run()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:  # inside an event loop
        return pool.submit(run).result()
