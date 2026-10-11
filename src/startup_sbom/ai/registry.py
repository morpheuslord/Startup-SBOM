"""Dynamic agent registry: built-ins, allow-listed entry-point plugins and remote agents.

Sources:

1. Built-in specialists (:data:`startup_sbom.ai.agents.BUILTINS`).
2. Python entry points in the ``startup_sbom.agents`` group, loaded **only** when their
   entry-point name is allow-listed (loading runs third-party code)::

       [project.entry-points."startup_sbom.agents"]
       compliance = "my_pkg:SPEC"   # an AgentSpec, or a callable returning one

3. Remote agents discovered by URL: A2A 1.0 agent cards
   (``/.well-known/agent-card.json``) and ACP manifests (``/agents``).  Remote calls use
   httpx with timeouts, no redirects, a response size cap, bearer auth when given, and
   only ever go to the user-specified origin.

Remote and plugin outputs are untrusted: they are spotlighted and grounding-checked
(flagged, never trusted) by the orchestrator.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import re
import uuid
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field, replace
from importlib.metadata import entry_points
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from startup_sbom.ai import INSTALL_HINT, AIConfigError, AIError, AIUnavailableError

try:
    from pydantic_ai import Agent
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise AIUnavailableError(f"the AI features need 'pydantic-ai': {INSTALL_HINT}") from exc

ENTRY_POINT_GROUP = "startup_sbom.agents"
MAX_REMOTE_BYTES = 1_000_000
DEFAULT_TIMEOUT = 60.0
Tier = Literal["cheap", "balanced", "quality"]
Protocol = Literal["a2a", "acp"]
_A2A_TERMINAL = {
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
    "completed",
    "failed",
    "canceled",
    "rejected",
}
_NAME_RE = re.compile(r"[^0-9a-zA-Z]+")


def ident(name: str) -> str:
    """A Python-identifier version of an agent name (``ask_<ident>`` tool names)."""
    out = _NAME_RE.sub("_", name).strip("_").lower() or "agent"
    return f"a_{out}" if out[0].isdigit() else out[:48]


def _loopback(host: str) -> bool:
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_remote_url(url: str, *, allow_insecure: bool = False) -> str:
    """Normalise a user-supplied agent URL: https, or http on loopback (or when allowed)."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AIConfigError(f"remote agent URL must be http(s)://host[:port][/path]: {url!r}")
    if parts.username or parts.password:
        raise AIConfigError("credentials in agent URLs are not allowed; use a bearer token")
    if parts.scheme == "http" and not (allow_insecure or _loopback(parts.hostname)):
        raise AIConfigError(f"refusing plain-http remote agent {url!r}: use https")
    return url.strip().rstrip("/")


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


@dataclass(frozen=True)
class RemoteAgent:
    """A remote agent reachable over A2A (JSON-RPC) or ACP (REST)."""

    protocol: Protocol
    base_url: str
    endpoint: str  # A2A JSON-RPC endpoint, or ACP base URL
    agent_name: str  # remote name (ACP agent_name / A2A card name)
    token: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    poll_interval: float = 0.5
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False, compare=False)

    def client(self) -> httpx.AsyncClient:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            follow_redirects=False,
            headers=headers,
            transport=self.transport,
        )

    async def call(self, task: str) -> Any:
        """Send ``task`` and return the remote agent's result (JSON-like, untrusted)."""
        async with self.client() as http:
            if self.protocol == "acp":
                return await self._call_acp(http, task)
            return await self._call_a2a(http, task)

    async def _post(self, http: httpx.AsyncClient, url: str, body: dict[str, Any]) -> Any:
        resp = await http.post(url, json=body)
        return _json(resp)

    async def _call_a2a(self, http: httpx.AsyncClient, task: str) -> Any:
        message = {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": task}],
        }
        sent = await self._post(
            http,
            self.endpoint,
            {"jsonrpc": "2.0", "id": "1", "method": "SendMessage", "params": {"message": message}},
        )
        result = _rpc_result(sent)
        task_obj = result.get("task", result)
        task_id = task_obj.get("id")
        if not isinstance(task_id, str):
            raise AIError("remote A2A agent returned no task id")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        while _state(task_obj) not in _A2A_TERMINAL:
            if loop.time() > deadline:
                raise AIError(f"remote A2A agent {self.agent_name!r} timed out")
            await asyncio.sleep(self.poll_interval)
            got = await self._post(
                http,
                self.endpoint,
                {"jsonrpc": "2.0", "id": "2", "method": "GetTask", "params": {"id": task_id}},
            )
            task_obj = _rpc_result(got)
        state = _state(task_obj)
        if state not in ("TASK_STATE_COMPLETED", "completed"):
            raise AIError(f"remote A2A agent {self.agent_name!r} ended in state {state}")
        parts = [p for a in task_obj.get("artifacts", []) or [] for p in a.get("parts", []) or []]
        values = [p.get("data", p.get("text")) for p in parts if isinstance(p, dict)]
        return values[0] if len(values) == 1 else values

    async def _call_acp(self, http: httpx.AsyncClient, task: str) -> Any:
        body = {
            "agent_name": self.agent_name,
            "input": [{"role": "user", "parts": [{"content_type": "text/plain", "content": task}]}],
            "mode": "sync",
        }
        run = await self._post(http, f"{self.endpoint}/runs", body)
        if not isinstance(run, dict):
            raise AIError("remote ACP agent returned a malformed run")
        if run.get("status") != "completed":
            error = run.get("error") or {}
            raise AIError(f"remote ACP run {run.get('status')}: {error.get('message', '')}"[:300])
        values: list[Any] = []
        for message in run.get("output", []) or []:
            for part in message.get("parts", []) or []:
                content = part.get("content")
                if "json" in str(part.get("content_type", "")) and isinstance(content, str):
                    with contextlib.suppress(ValueError):
                        content = json.loads(content)
                values.append(content)
        return values[0] if len(values) == 1 else values


def _json(resp: httpx.Response) -> Any:
    if resp.status_code in (401, 403):
        raise AIError(f"remote agent refused the request ({resp.status_code}); check the token")
    if resp.status_code >= 400:
        raise AIError(f"remote agent HTTP {resp.status_code}")
    if len(resp.content) > MAX_REMOTE_BYTES:
        raise AIError("remote agent response exceeds the size cap")
    try:
        return resp.json()
    except ValueError as exc:
        raise AIError("remote agent returned invalid JSON") from exc


def _rpc_result(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AIError("malformed JSON-RPC response")
    if "error" in payload:
        err = payload["error"] or {}
        raise AIError(f"remote A2A error: {str(err.get('message', err))[:200]}")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise AIError("JSON-RPC response has no result")
    return result


def _state(task: dict[str, Any]) -> str:
    status = task.get("status") or {}
    return str(status.get("state", ""))


@dataclass(frozen=True)
class AgentSpec:
    """A specialist the orchestrator can delegate to (local builder or remote agent)."""

    name: str
    description: str
    build: Callable[[Any], Agent[Any, Any]] | None = None  # model -> Agent
    remote: RemoteAgent | None = None
    tags: tuple[str, ...] = ()
    tier: Tier = "cheap"  # cheap -> specialist model; balanced/quality -> orchestrator model
    source: str = "builtin"  # builtin | entry-point:<dist> | a2a:<url> | acp:<url>
    inject_report_tools: bool = True

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise AIConfigError(f"agent name must be a Python identifier: {self.name!r}")
        if (self.build is None) == (self.remote is None):
            raise AIConfigError(f"agent {self.name!r} needs exactly one of build= or remote=")

    @property
    def trusted(self) -> bool:
        return self.source == "builtin"


class AgentRegistry:
    """Mutable set of specialists; the orchestrator rebuilds its ``ask_*`` tools per run."""

    def __init__(self, specs: Iterable[AgentSpec] = ()) -> None:
        self._specs: dict[str, AgentSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: AgentSpec, *, replace_existing: bool = False) -> AgentSpec:
        if spec.name in self._specs and not replace_existing:
            raise AIConfigError(
                f"duplicate agent {spec.name!r} ({self._specs[spec.name].source} vs {spec.source})"
            )
        self._specs[spec.name] = spec
        return spec

    def unregister(self, name: str) -> None:
        self._specs.pop(name, None)

    def get(self, name: str) -> AgentSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise AIConfigError(
                f"unknown agent {name!r} (available: {', '.join(self.names()) or 'none'})"
            ) from None

    def names(self) -> list[str]:
        return list(self._specs)

    def specs(self) -> list[AgentSpec]:
        return list(self._specs.values())

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def select(self, names: Iterable[str]) -> AgentRegistry:
        """A registry with only ``names`` (raises on unknown names)."""
        return AgentRegistry(self.get(n.strip()) for n in names if n.strip())

    def _unique(self, name: str) -> str:
        base, n = ident(name), 2
        out = base
        while out in self._specs:
            out, n = f"{base}_{n}", n + 1
        return out

    # ------------------------------------------------------------------ plugins
    def load_entry_points(self, allow: Collection[str]) -> list[str]:
        """Load allow-listed ``startup_sbom.agents`` entry points; returns registered names."""
        if not allow:
            return []
        loaded: list[str] = []
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            if ep.name not in allow:
                continue
            obj = ep.load()
            spec = obj() if callable(obj) and not isinstance(obj, AgentSpec) else obj
            if not isinstance(spec, AgentSpec):
                raise AIConfigError(f"entry point {ep.value!r} did not provide an AgentSpec")
            dist = ep.dist.name if ep.dist is not None else "unknown"
            loaded.append(self.register(replace(spec, source=f"entry-point:{dist}")).name)
        missing = set(allow) - {ep.name for ep in entry_points(group=ENTRY_POINT_GROUP)}
        if missing:
            raise AIConfigError(f"allow-listed agent plugin(s) not installed: {sorted(missing)}")
        return loaded

    # ------------------------------------------------------------------ remote
    async def add_remote(
        self,
        url: str,
        *,
        protocol: Literal["auto", "a2a", "acp"] = "auto",
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        allow_insecure: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> list[AgentSpec]:
        """Discover remote agent(s) at ``url`` and register them; returns the new specs."""
        base = validate_remote_url(url, allow_insecure=allow_insecure)
        proto = RemoteAgent("a2a", base, base, "", token, timeout, transport=transport)
        async with proto.client() as http:
            if protocol in ("auto", "a2a"):
                resp = await http.get(f"{base}/.well-known/agent-card.json")
                if resp.status_code == 200 or protocol == "a2a":
                    return [self._register_a2a(base, _json(resp), proto)]
            resp = await http.get(f"{base}/agents")
            manifests = _json(resp)
        agents = manifests.get("agents") if isinstance(manifests, dict) else None
        if not isinstance(agents, list):
            raise AIError(f"{base} is neither an A2A agent nor an ACP server")
        return [self._register_acp(base, m, proto) for m in agents if isinstance(m, dict)]

    def _register_a2a(self, base: str, card: Any, proto: RemoteAgent) -> AgentSpec:
        if not isinstance(card, dict) or not isinstance(card.get("name"), str):
            raise AIError("malformed A2A agent card")
        interfaces = card.get("supportedInterfaces") or card.get("supported_interfaces") or []
        endpoint = base + "/"
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            if str(iface.get("protocolBinding", "JSONRPC")) == "JSONRPC":
                endpoint = str(iface.get("url") or endpoint)
                break
        if not _same_origin(endpoint, base):
            endpoint = base + "/"  # never follow a card to an origin the user did not name
        skills = card.get("skills") or []
        tags = tuple(str(t) for s in skills if isinstance(s, dict) for t in s.get("tags", []) or [])
        remote = replace(proto, protocol="a2a", endpoint=endpoint, agent_name=card["name"])
        return self.register(
            AgentSpec(
                name=self._unique(card["name"]),
                description=str(card.get("description", ""))[:300],
                remote=remote,
                tags=tags[:10],
                source=f"a2a:{base}",
            )
        )

    def _register_acp(self, base: str, manifest: dict[str, Any], proto: RemoteAgent) -> AgentSpec:
        name = str(manifest.get("name", ""))
        if not name:
            raise AIError("malformed ACP agent manifest")
        meta = manifest.get("metadata") or {}
        remote = replace(proto, protocol="acp", endpoint=base, agent_name=name)
        return self.register(
            AgentSpec(
                name=self._unique(name),
                description=str(manifest.get("description", ""))[:300],
                remote=remote,
                tags=tuple(str(t) for t in (meta.get("tags") or []))[:10],
                source=f"acp:{base}",
            )
        )

    def describe(self) -> list[dict[str, Any]]:
        """Rows for listing (name, source, tier, description, tags)."""
        return [
            {
                "name": s.name,
                "source": s.source,
                "tier": s.tier,
                "trusted": s.trusted,
                "description": s.description,
                "tags": list(s.tags),
            }
            for s in self._specs.values()
        ]


def builtin_specs() -> list[AgentSpec]:
    """The built-in specialists."""
    from startup_sbom.ai.agents import BUILTINS

    return [
        AgentSpec(name=name, description=desc, build=build, tags=("builtin",))
        for name, (desc, _output, build) in BUILTINS.items()
    ]


async def build_registry(
    *,
    plugins: Collection[str] = (),
    remote: Iterable[str] = (),
    token: str | None = None,
    builtins: bool = True,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AgentRegistry:
    """Built-ins + allow-listed plugins + remote agents at the given URLs."""
    registry = AgentRegistry(builtin_specs() if builtins else ())
    registry.load_entry_points(plugins)
    for url in remote:
        await registry.add_remote(url, token=token, transport=transport)
    return registry
