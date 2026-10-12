"""Serve the orchestrator and specialists over A2A 1.0 with ``fasta2a``.

Pydantic AI 2 removed ``Agent.to_a2a()``; the replacement is building ``FastA2A``
around ``fasta2a.pydantic_ai.AgentWorker``, with two fixes verified against the
official ``a2a-sdk`` client:

1. **deps**: the worker calls ``agent.run(message_history=...)`` without deps, so the
   lifespan binds them with ``agent.override(deps=...)`` (contextvars propagate into
   the worker's task group).
2. **timestamps**: fasta2a 2.1.1 writes naive timestamps the a2a-sdk (protobuf JSON)
   rejects; :class:`UTCStorage` rewrites them as UTC ``...Z``.

The orchestrator card is served at the root; each local specialist gets its own card
under ``/agents/<name>``.  Binds 127.0.0.1 by default; a bearer token
(``STARTUP_SBOM_AGENT_TOKEN``) is required on any other interface.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import AsyncExitStack, ExitStack, asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from startup_sbom.ai import SERVER_INSTALL_HINT, AIUnavailableError
from startup_sbom.ai.acp import TokenAuthMiddleware
from startup_sbom.ai.index import ReportIndex
from startup_sbom.ai.orchestrator import ModelSet, build_orchestrator
from startup_sbom.ai.registry import AgentRegistry, AgentSpec
from startup_sbom.ai.tools import AgentDeps, report_toolset
from startup_sbom.models import Report

try:
    from fasta2a import FastA2A
    from fasta2a.broker import InMemoryBroker
    from fasta2a.pydantic_ai import AgentWorker
    from fasta2a.schema import AgentProvider, Artifact, Message, Skill, Task, TaskState
    from fasta2a.storage import InMemoryStorage
    from pydantic_ai import Agent
    from starlette.applications import Starlette
    from starlette.routing import BaseRoute, Mount
    from starlette.types import ASGIApp
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the A2A server needs 'fasta2a': {SERVER_INSTALL_HINT}") from exc

PROVIDER = AgentProvider(
    organization="startup-sbom", url="https://github.com/morpheuslord/Startup-SBOM"
)


class UTCStorage(InMemoryStorage):  # type: ignore[misc] # fasta2a ships no types
    """``InMemoryStorage`` whose task timestamps are UTC with a ``Z`` suffix.

    fasta2a 2.1.1 writes ``datetime.now().isoformat()`` (naive, no zone); the official
    a2a-sdk client fails to parse that protobuf timestamp.  Worth fixing upstream.
    """

    @staticmethod
    def _utc(task: Task) -> Task:
        status = task.get("status")
        if status is not None:
            status["timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return task

    async def submit_task(self, context_id: str, message: Message) -> Task:
        return self._utc(await super().submit_task(context_id, message))

    async def update_task(
        self,
        task_id: str,
        state: TaskState,
        new_artifacts: list[Artifact] | None = None,
        new_messages: list[Message] | None = None,
    ) -> Task:
        return self._utc(await super().update_task(task_id, state, new_artifacts, new_messages))


def agent_app(
    agent: Agent[AgentDeps, Any],
    deps: AgentDeps,
    *,
    name: str,
    description: str,
    url: str,
    skills: list[Skill],
    version: str,
    extra_toolsets: bool = True,
) -> FastA2A:
    """One A2A app (card + JSON-RPC) around ``agent`` with deps bound in the lifespan."""
    storage, broker = UTCStorage(), InMemoryBroker()
    worker = AgentWorker(agent=agent, broker=broker, storage=storage)

    @asynccontextmanager
    async def lifespan(app: FastA2A) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(app.task_manager)
            await stack.enter_async_context(agent)
            overrides = ExitStack()
            stack.enter_context(overrides)
            if extra_toolsets:
                overrides.enter_context(agent.override(deps=deps, toolsets=[report_toolset()]))
            else:
                overrides.enter_context(agent.override(deps=deps))
            await stack.enter_async_context(worker.run())
            yield

    return FastA2A(
        storage=storage,
        broker=broker,
        name=name,
        url=url,
        version=version,
        description=description,
        provider=PROVIDER,
        skills=skills,
        default_input_modes=["text/plain"],
        default_output_modes=["application/json"],
        lifespan=lifespan,
    )


def _skill(spec: AgentSpec) -> Skill:
    return Skill(
        id=spec.name,
        name=spec.name.replace("_", " "),
        description=spec.description,
        tags=list(dict.fromkeys([*spec.tags, "security", "sbom"])),
        input_modes=["text/plain"],
        output_modes=["application/json"],
    )


def build_a2a_apps(
    report: Report,
    *,
    models: ModelSet,
    registry: AgentRegistry,
    base_url: str = "http://127.0.0.1:8770",
) -> dict[str, FastA2A]:
    """``{"": orchestrator app, "<name>": specialist app, ...}`` keyed by mount name."""
    from startup_sbom import __version__

    deps = AgentDeps(index=ReportIndex(report))
    apps: dict[str, FastA2A] = {}
    orchestrator = build_orchestrator(registry, models)
    apps[""] = agent_app(
        orchestrator,
        deps,
        name="startup-sbom-orchestrator",
        description=(
            "Lead analyst over one startup-sbom scan report: delegates to specialists "
            "and returns one grounded, machine-checked assessment (read-only)."
        ),
        url=base_url,
        skills=[_skill(spec) for spec in registry.specs()],
        version=__version__,
        extra_toolsets=False,  # the orchestrator already owns its toolsets
    )
    for spec in registry.specs():
        if spec.build is None:
            continue  # remote agents are consumed, never re-exposed
        model = models.orchestrator if spec.tier != "cheap" else models.specialist
        apps[spec.name] = agent_app(
            spec.build(model),
            deps,
            name=f"startup-sbom-{spec.name.replace('_', '-')}",
            description=spec.description,
            url=f"{base_url}/agents/{spec.name}",
            skills=[_skill(spec)],
            version=__version__,
            extra_toolsets=spec.inject_report_tools,
        )
    return apps


def build_a2a_app(
    report: Report,
    *,
    models: ModelSet,
    registry: AgentRegistry,
    base_url: str = "http://127.0.0.1:8770",
    token: str | None = None,
    extra_routes: Sequence[BaseRoute] = (),
) -> ASGIApp:
    """One ASGI app: orchestrator at ``/``, specialists at ``/agents/<name>``.

    Mounted Starlette apps get no lifespan events, so the parent lifespan enters each
    sub-app's lifespan (task manager, ``agent.override(deps=...)``, worker) itself.
    ``extra_routes`` (e.g. a ``Mount("/acp", ...)``) are matched before the root app.
    """
    apps = build_a2a_apps(report, models=models, registry=registry, base_url=base_url)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            for sub in apps.values():
                await stack.enter_async_context(sub.router.lifespan_context(sub))
            yield

    routes: list[BaseRoute] = [
        Mount(f"/agents/{name}", app=sub) for name, sub in apps.items() if name
    ]
    routes.extend(extra_routes)
    routes.append(Mount("/", app=apps[""]))
    app: ASGIApp = Starlette(routes=routes, lifespan=lifespan)
    if token:
        app = TokenAuthMiddleware(app, token)
    return app
