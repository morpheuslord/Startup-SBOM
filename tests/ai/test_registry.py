"""Agent registry: built-ins, allow-listed entry-point plugins, remote A2A/ACP agents."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from canned import good_triage
from pydantic_ai import Agent

from startup_sbom.ai import AIConfigError, AIError
from startup_sbom.ai import registry as reg
from startup_sbom.ai.registry import (
    AgentRegistry,
    AgentSpec,
    RemoteAgent,
    build_registry,
    builtin_specs,
    ident,
    validate_remote_url,
)

BUILTIN_NAMES = {
    "triage",
    "exploitability",
    "attack_chains",
    "supply_chain",
    "remediation",
    "executive",
}


def _build(model: Any) -> Agent[Any, Any]:
    return Agent(model, output_type=str, defer_model_check=True)


def spec(name: str = "demo", **kw: Any) -> AgentSpec:
    kw.setdefault("build", _build)
    return AgentSpec(name=name, description="demo agent", **kw)


# --------------------------------------------------------------------------- basics
def test_ident() -> None:
    assert ident("Remote Triage!") == "remote_triage"
    assert ident("42agents") == "a_42agents"
    assert ident("---") == "agent"


def test_validate_remote_url() -> None:
    assert validate_remote_url("https://agents.example/a2a/") == "https://agents.example/a2a"
    assert validate_remote_url("http://127.0.0.1:8770") == "http://127.0.0.1:8770"
    assert validate_remote_url("http://localhost:1234") == "http://localhost:1234"
    with pytest.raises(AIConfigError, match="use https"):
        validate_remote_url("http://agents.example")
    validate_remote_url("http://agents.example", allow_insecure=True)
    with pytest.raises(AIConfigError, match="bearer token"):
        validate_remote_url("https://user:pw@agents.example")
    with pytest.raises(AIConfigError, match="http"):
        validate_remote_url("ftp://agents.example")


def test_agent_spec_validation() -> None:
    with pytest.raises(AIConfigError, match="identifier"):
        spec(name="not a name")
    with pytest.raises(AIConfigError, match="exactly one"):
        AgentSpec(name="x", description="d")
    assert spec().trusted  # builtin source
    assert not spec(source="entry-point:demo").trusted


def test_registry_register_select() -> None:
    registry = AgentRegistry(builtin_specs())
    assert set(registry.names()) == BUILTIN_NAMES
    with pytest.raises(AIConfigError, match="duplicate"):
        registry.register(spec("triage"))
    registry.register(spec("triage"), replace_existing=True)
    picked = registry.select(["triage", "remediation"])
    assert picked.names() == ["triage", "remediation"]
    with pytest.raises(AIConfigError, match="unknown agent"):
        registry.select(["nope"])
    assert "triage" in registry
    assert len(picked) == 2


# --------------------------------------------------------------------------- entry points
@dataclass
class FakeEntryPoint:
    name: str
    obj: Any
    dist: Any = None
    value: str = "fake_plugin:SPEC"

    def load(self) -> Any:
        return self.obj


def test_entry_points_allow_list(monkeypatch: pytest.MonkeyPatch) -> None:
    compliance = spec("compliance", source="builtin")
    eps = [FakeEntryPoint("compliance", compliance), FakeEntryPoint("evil", spec("evil"))]
    monkeypatch.setattr(reg, "entry_points", lambda *, group: list(eps))

    registry = AgentRegistry()
    assert registry.load_entry_points(()) == []  # nothing without an allow-list

    loaded = registry.load_entry_points({"compliance"})
    assert loaded == ["compliance"]
    assert registry.get("compliance").source == "entry-point:unknown"
    assert not registry.get("compliance").trusted
    assert "evil" not in registry  # not allow-listed, never loaded

    with pytest.raises(AIConfigError, match="not installed"):
        AgentRegistry().load_entry_points({"compliance", "missing"})


def test_entry_point_callable_and_bad_value(monkeypatch: pytest.MonkeyPatch) -> None:
    factory = FakeEntryPoint("factory", lambda: spec("factory"))
    bogus = FakeEntryPoint("bogus", object())
    monkeypatch.setattr(reg, "entry_points", lambda *, group: [factory, bogus])
    registry = AgentRegistry()
    assert registry.load_entry_points({"factory"}) == ["factory"]
    with pytest.raises(AIConfigError, match="AgentSpec"):
        AgentRegistry().load_entry_points({"bogus"})


# --------------------------------------------------------------------------- remote: A2A
def a2a_transport(
    *, state_sequence: list[str] | None = None, cross_origin_endpoint: bool = False
) -> httpx.MockTransport:
    states = state_sequence or ["TASK_STATE_WORKING", "TASK_STATE_COMPLETED"]
    polls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/agent-card.json"):
            endpoint = (
                "https://evil.example/" if cross_origin_endpoint else "https://agents.example/"
            )
            return httpx.Response(
                200,
                json={
                    "name": "Remote Triage",
                    "description": "ranks threats remotely",
                    "supportedInterfaces": [{"protocolBinding": "JSONRPC", "url": endpoint}],
                    "skills": [{"id": "triage", "tags": ["security"]}],
                },
            )
        body = json.loads(request.content)
        if body["method"] == "SendMessage":
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {"task": {"id": "task-1", "status": {"state": states[0]}}},
                },
            )
        assert body["method"] == "GetTask"
        polls["n"] += 1
        state = states[min(polls["n"], len(states) - 1)]
        task: dict[str, Any] = {"id": "task-1", "status": {"state": state}}
        if state == "TASK_STATE_COMPLETED":
            task["artifacts"] = [{"parts": [{"data": good_triage()}]}]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": task})

    return httpx.MockTransport(handler)


def test_add_remote_a2a_and_call() -> None:
    async def main() -> None:
        registry = AgentRegistry()
        specs = await registry.add_remote(
            "https://agents.example",
            token="sekrit",  # noqa: S106 - test fixture value
            transport=a2a_transport(),
        )
        assert [s.name for s in specs] == ["remote_triage"]
        remote = specs[0].remote
        assert remote is not None
        assert remote.protocol == "a2a"
        assert specs[0].source == "a2a:https://agents.example"
        assert not specs[0].trusted
        fast = reg.replace(remote, poll_interval=0.01)
        result = await fast.call("rank the threats")
        assert result["findings"][0]["threat_id"] == "TH-0001"

    asyncio.run(main())


def test_a2a_card_cannot_redirect_to_other_origin() -> None:
    async def main() -> None:
        registry = AgentRegistry()
        specs = await registry.add_remote(
            "https://agents.example", transport=a2a_transport(cross_origin_endpoint=True)
        )
        remote = specs[0].remote
        assert remote is not None
        assert remote.endpoint == "https://agents.example/"  # never the card's foreign origin

    asyncio.run(main())


def test_a2a_failed_task_raises() -> None:
    async def main() -> None:
        registry = AgentRegistry()
        specs = await registry.add_remote(
            "https://agents.example",
            transport=a2a_transport(state_sequence=["TASK_STATE_WORKING", "TASK_STATE_FAILED"]),
        )
        remote = specs[0].remote
        assert remote is not None
        with pytest.raises(AIError, match="TASK_STATE_FAILED"):
            await reg.replace(remote, poll_interval=0.01).call("x")

    asyncio.run(main())


# --------------------------------------------------------------------------- remote: ACP
def acp_transport() -> httpx.MockTransport:
    manifest = {
        "name": "acp-triage",
        "description": "ACP remote",
        "metadata": {"tags": ["acp"]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/agent-card.json"):
            return httpx.Response(404)
        if request.method == "GET" and request.url.path.endswith("/agents"):
            return httpx.Response(200, json={"agents": [manifest]})
        assert request.url.path.endswith("/runs")
        return httpx.Response(
            200,
            json={
                "run_id": "r1",
                "status": "completed",
                "output": [
                    {
                        "role": "agent/acp-triage",
                        "parts": [
                            {
                                "content_type": "application/json",
                                "content": json.dumps(good_triage()),
                            }
                        ],
                    }
                ],
            },
        )

    return httpx.MockTransport(handler)


def test_add_remote_acp_discovery_and_call() -> None:
    async def main() -> None:
        registry = await build_registry(remote=["https://acp.example"], transport=acp_transport())
        assert "acp_triage" in registry.names()
        spec = registry.get("acp_triage")
        assert spec.source == "acp:https://acp.example"
        assert spec.remote is not None
        assert spec.remote.protocol == "acp"
        result = await spec.remote.call("rank")
        assert result["findings"][0]["priority"] == "P1"

    asyncio.run(main())


def test_remote_errors() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async def main() -> None:
        remote = RemoteAgent(
            "acp",
            "https://x.example",
            "https://x.example",
            "a",
            transport=httpx.MockTransport(refuse),
        )
        with pytest.raises(AIError, match="401"):
            await remote.call("x")

    asyncio.run(main())
