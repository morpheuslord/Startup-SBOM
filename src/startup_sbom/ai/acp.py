"""ACP REST facade: serve the agent registry over the Agent Communication Protocol.

``acp-sdk`` is archived (it merged into A2A in 2025 and breaks on uvicorn >= 0.35), so
this is a dependency-free Starlette implementation of the subset ACP clients use:
``GET /ping``, ``GET /agents``, ``GET /agents/{name}`` (manifest), ``POST /runs``
(``sync`` | ``async`` | ``stream``) and ``GET /runs/{id}``.  Only *local* agents
(built-ins and allow-listed plugins) are exposed; remote agents are never proxied.

Binds 127.0.0.1 by default.  A bearer token (``STARTUP_SBOM_AGENT_TOKEN``) is
optional on loopback and **required** on any other interface.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from startup_sbom.ai import INSTALL_HINT, AIConfigError, AIUnavailableError
from startup_sbom.ai.index import ReportIndex, sanitize
from startup_sbom.ai.orchestrator import ModelSet, build_orchestrator
from startup_sbom.ai.registry import AgentRegistry, AgentSpec
from startup_sbom.ai.tools import AgentDeps, report_toolset
from startup_sbom.models import Report
from startup_sbom.textsafe import clean

try:
    from pydantic import BaseModel
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response, StreamingResponse
    from starlette.routing import Route
    from starlette.types import ASGIApp, Receive, Scope, Send
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the agent servers need 'starlette': {INSTALL_HINT}") from exc

MAX_BODY_BYTES = 262_144
MAX_PROMPT_CHARS = 20_000
TOKEN_ENV = "STARTUP_SBOM_AGENT_TOKEN"  # noqa: S105 - env var name, not a secret


def is_loopback_host(host: str) -> bool:
    """Whether ``host`` only binds/means the loopback interface."""
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def require_token(host: str, token: str | None) -> None:
    """Refuse to serve agents on a non-loopback interface without a bearer token."""
    if token is None and not is_loopback_host(host):
        raise AIConfigError(
            f"refusing to bind {host!r} without authentication: set {TOKEN_ENV} (or bind 127.0.0.1)"
        )


class TokenAuthMiddleware:
    """Require ``Authorization: Bearer <token>`` on every request."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            if headers.get(b"authorization") != self._expected:
                response = JSONResponse(
                    {"code": "unauthorized", "message": "missing or wrong bearer token"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


# --------------------------------------------------------------------------- facade
Runner = Callable[[str], Awaitable[tuple[str, str]]]


@dataclass(frozen=True)
class _Served:
    manifest: dict[str, Any]
    run: Runner


def _manifest(spec: AgentSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "metadata": {
            "tags": list(spec.tags),
            "framework": "pydantic-ai",
            "capabilities": [{"name": "grounded-analysis"}],
            "author": {"name": "startup-sbom"},
        },
        "input_content_types": ["text/plain"],
        "output_content_types": ["application/json"],
    }


def _runner(spec: AgentSpec, models: ModelSet, deps: AgentDeps) -> Runner:
    model = models.orchestrator if spec.tier != "cheap" else models.specialist

    async def run(prompt: str) -> tuple[str, str]:
        assert spec.build is not None  # noqa: S101 - remote specs are filtered out
        agent = spec.build(model)
        toolsets = [report_toolset()] if spec.inject_report_tools else None
        result = await agent.run(prompt, deps=deps, toolsets=toolsets)
        output = result.output
        if isinstance(output, BaseModel):
            return output.model_dump_json(), "application/json"
        return json.dumps(sanitize(output), default=str), "application/json"

    return run


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status)


def build_acp_app(
    report: Report,
    *,
    models: ModelSet,
    registry: AgentRegistry,
    include_orchestrator: bool = True,
    token: str | None = None,
) -> ASGIApp:
    """The ACP facade app over ``registry`` (local agents) plus the orchestrator."""
    deps = AgentDeps(index=ReportIndex(report))
    served: dict[str, _Served] = {}
    for spec in registry.specs():
        if spec.build is None:
            continue  # never proxy remote agents
        served[spec.name] = _Served(_manifest(spec), _runner(spec, models, deps))
    if include_orchestrator:
        orchestrator = build_orchestrator(registry, models)

        async def run_orchestrator(prompt: str) -> tuple[str, str]:
            result = await orchestrator.run(prompt, deps=deps)
            return result.output.model_dump_json(), "application/json"

        served["orchestrator"] = _Served(
            {
                "name": "orchestrator",
                "description": (
                    "Lead analyst: delegates to the specialists and synthesises one "
                    "grounded assessment of the loaded scan report"
                ),
                "metadata": {"tags": ["orchestrator"], "framework": "pydantic-ai"},
                "input_content_types": ["text/plain"],
                "output_content_types": ["application/json"],
            },
            run_orchestrator,
        )
    runs: dict[str, dict[str, Any]] = {}
    background: set[asyncio.Task[None]] = set()

    async def ping(_: Request) -> Response:
        return JSONResponse({})

    async def list_agents(_: Request) -> Response:
        return JSONResponse({"agents": [s.manifest for s in served.values()]})

    async def get_agent(request: Request) -> Response:
        entry = served.get(request.path_params["name"])
        if entry is None:
            return _error("not_found", "agent not found", 404)
        return JSONResponse(entry.manifest)

    async def get_run(request: Request) -> Response:
        run = runs.get(request.path_params["run_id"])
        if run is None:
            return _error("not_found", "run not found", 404)
        return JSONResponse(run)

    async def create_run(request: Request) -> Response:
        body_bytes = await request.body()
        if len(body_bytes) > MAX_BODY_BYTES:
            return _error("invalid_input", "request body too large", 413)
        try:
            body = json.loads(body_bytes)
        except ValueError:
            return _error("invalid_input", "body is not JSON", 400)
        if not isinstance(body, dict):
            return _error("invalid_input", "body must be a JSON object", 400)
        entry = served.get(str(body.get("agent_name", "")))
        if entry is None:
            return _error("not_found", "agent not found", 404)
        parts = [
            str(part.get("content") or "")
            for message in body.get("input") or []
            if isinstance(message, dict)
            for part in message.get("parts") or []
            if isinstance(part, dict)
        ]
        prompt = clean("\n".join(parts), max_len=MAX_PROMPT_CHARS, keep_newlines=True)
        run: dict[str, Any] = {
            "run_id": str(uuid.uuid4()),
            "agent_name": body["agent_name"],
            "session_id": body.get("session_id"),
            "status": "in-progress",
            "output": [],
            "error": None,
            "created_at": _now(),
            "finished_at": None,
        }
        runs[run["run_id"]] = run

        async def execute() -> None:
            try:
                content, ctype = await entry.run(prompt)
                run["output"] = [
                    {
                        "role": f"agent/{run['agent_name']}",
                        "parts": [{"content_type": ctype, "content": content}],
                        "created_at": _now(),
                        "completed_at": _now(),
                    }
                ]
                run["status"] = "completed"
            except Exception as exc:  # noqa: BLE001 - reported to the caller as a failed run
                run["status"] = "failed"
                run["error"] = {
                    "code": "server_error",
                    "message": clean(str(exc), max_len=300),
                }
            run["finished_at"] = _now()

        mode = body.get("mode", "sync")
        if mode == "async":
            task = asyncio.create_task(execute())
            background.add(task)
            task.add_done_callback(background.discard)
            return JSONResponse(run, status_code=202)
        if mode == "stream":

            async def sse() -> Any:
                yield f"data: {json.dumps({'type': 'run.created', 'run': run})}\n\n"
                await execute()
                for message in run["output"]:
                    for part in message["parts"]:
                        yield f"data: {json.dumps({'type': 'message.part', 'part': part})}\n\n"
                yield f"data: {json.dumps({'type': 'run.' + run['status'], 'run': run})}\n\n"

            return StreamingResponse(sse(), media_type="text/event-stream")
        await execute()
        return JSONResponse(run)

    app: ASGIApp = Starlette(
        routes=[
            Route("/ping", ping),
            Route("/agents", list_agents),
            Route("/agents/{name}", get_agent),
            Route("/runs", create_run, methods=["POST"]),
            Route("/runs/{run_id}", get_run),
        ]
    )
    if token:
        app = TokenAuthMiddleware(app, token)
    return app
