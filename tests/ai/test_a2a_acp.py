"""A2A (fasta2a, with the deps-override and UTC-timestamp fixes) and the ACP facade."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import httpx
import pytest
from canned import good_assessment, good_triage
from pydantic_ai import ModelResponse, ToolCallPart
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models.function import AgentInfo, FunctionModel
from starlette.testclient import TestClient

from startup_sbom.ai import AIConfigError
from startup_sbom.ai.a2a import build_a2a_app
from startup_sbom.ai.acp import build_acp_app, is_loopback_host, require_token
from startup_sbom.ai.orchestrator import ModelSet
from startup_sbom.ai.registry import AgentRegistry, builtin_specs
from startup_sbom.models import Report

TERMINAL = {"completed", "failed", "canceled", "rejected"}


def canned_models() -> ModelSet:
    """Orchestrator -> FinalAssessment, any specialist -> TriageReport, instantly."""

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        output_tool = info.output_tools[0].name
        if any(t.name.startswith("ask_") for t in info.function_tools):
            return ModelResponse(parts=[ToolCallPart(output_tool, good_assessment())])
        return ModelResponse(parts=[ToolCallPart(output_tool, good_triage())])

    return ModelSet.single(FunctionModel(fn))


def registry() -> AgentRegistry:
    return AgentRegistry(builtin_specs()).select(["triage"])


def rpc(client: TestClient, method: str, params: dict[str, Any], path: str = "/") -> Any:
    body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
    response = client.post(path, json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "error" not in payload, payload
    return payload["result"]


def wait_terminal(client: TestClient, task_id: str, path: str = "/") -> dict[str, Any]:
    for _ in range(200):
        task = rpc(client, "GetTask", {"id": task_id}, path)
        state = str(task["status"]["state"]).lower().removeprefix("task_state_")
        if state in TERMINAL:
            return task
        time.sleep(0.02)
    raise AssertionError("A2A task never reached a terminal state")


# --------------------------------------------------------------------------- A2A
def test_a2a_cards_and_sync_run(report: Report) -> None:
    app = build_a2a_app(
        report, models=canned_models(), registry=registry(), base_url="http://testserver"
    )
    with TestClient(app) as client:
        card = client.get("/.well-known/agent-card.json").json()
        assert card["name"] == "startup-sbom-orchestrator"
        interface = card["supportedInterfaces"][0]
        assert interface["url"] == "http://testserver"
        assert interface["protocolVersion"] == "1.0"
        assert card["capabilities"]["streaming"] is True
        assert [s["id"] for s in card["skills"]] == ["triage"]

        sub = client.get("/agents/triage/.well-known/agent-card.json").json()
        assert sub["name"] == "startup-sbom-triage"

        message = {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": "assess this scan"}],
        }
        sent = rpc(client, "SendMessage", {"message": message})
        task = sent.get("task", sent)
        done = wait_terminal(client, task["id"])
        state = str(done["status"]["state"]).lower()
        assert state.endswith("completed")
        # fix 2: the timestamp is UTC with a Z suffix (a2a-sdk interop)
        assert done["status"]["timestamp"].endswith("Z")
        parts = [p for a in done.get("artifacts") or [] for p in a.get("parts", [])]
        data = next(p["data"] for p in parts if "data" in p)
        data = data.get("result", data)  # fasta2a wraps pydantic outputs under "result"
        # fix 1: deps were bound via agent.override, so the grounded run succeeded
        assert data["findings"][0]["threat_id"] == "TH-0001"


def test_a2a_specialist_runs_with_deps(report: Report) -> None:
    app = build_a2a_app(
        report, models=canned_models(), registry=registry(), base_url="http://testserver"
    )
    with TestClient(app) as client:
        message = {
            "messageId": str(uuid.uuid4()),
            "role": "ROLE_USER",
            "parts": [{"text": "rank the threats"}],
        }
        sent = rpc(client, "SendMessage", {"message": message}, path="/agents/triage/")
        task = sent.get("task", sent)
        done = wait_terminal(client, task["id"], path="/agents/triage/")
        assert str(done["status"]["state"]).lower().endswith("completed")


def test_a2a_token_required(report: Report) -> None:
    app = build_a2a_app(
        report,
        models=canned_models(),
        registry=registry(),
        token="sekrit",  # noqa: S106
    )
    with TestClient(app) as client:
        assert client.get("/.well-known/agent-card.json").status_code == 401
        ok = client.get("/.well-known/agent-card.json", headers={"Authorization": "Bearer sekrit"})
        assert ok.status_code == 200


# --------------------------------------------------------------------------- ACP facade
@pytest.fixture
def acp_client(report: Report) -> TestClient:
    app = build_acp_app(report, models=canned_models(), registry=registry())
    return TestClient(app)


def test_acp_discovery(acp_client: TestClient) -> None:
    assert acp_client.get("/ping").json() == {}
    agents = acp_client.get("/agents").json()["agents"]
    names = {a["name"] for a in agents}
    assert names == {"triage", "orchestrator"}
    manifest = acp_client.get("/agents/triage").json()
    assert manifest["metadata"]["framework"] == "pydantic-ai"
    assert manifest["output_content_types"] == ["application/json"]
    assert acp_client.get("/agents/nope").status_code == 404


def test_acp_sync_run(acp_client: TestClient) -> None:
    body = {
        "agent_name": "triage",
        "input": [{"role": "user", "parts": [{"content_type": "text/plain", "content": "rank"}]}],
        "mode": "sync",
    }
    run = acp_client.post("/runs", json=body).json()
    assert run["status"] == "completed", run
    content = json.loads(run["output"][0]["parts"][0]["content"])
    assert content["findings"][0]["threat_id"] == "TH-0001"
    again = acp_client.get(f"/runs/{run['run_id']}").json()
    assert again["status"] == "completed"
    assert acp_client.get("/runs/missing").status_code == 404


def test_acp_orchestrator_run(acp_client: TestClient) -> None:
    body = {
        "agent_name": "orchestrator",
        "input": [{"role": "user", "parts": [{"content_type": "text/plain", "content": "go"}]}],
        "mode": "sync",
    }
    run = acp_client.post("/runs", json=body).json()
    assert run["status"] == "completed", run
    content = json.loads(run["output"][0]["parts"][0]["content"])
    assert "executive_summary" in content


def test_acp_stream_run(acp_client: TestClient) -> None:
    body = {
        "agent_name": "triage",
        "input": [{"role": "user", "parts": [{"content_type": "text/plain", "content": "rank"}]}],
        "mode": "stream",
    }
    with acp_client.stream("POST", "/runs", json=body) as response:
        events = [
            json.loads(line[6:]) for line in response.iter_lines() if line.startswith("data: ")
        ]
    kinds = [e["type"] for e in events]
    assert kinds[0] == "run.created"
    assert "message.part" in kinds
    assert kinds[-1] == "run.completed"


def test_acp_unknown_agent_and_bad_body(acp_client: TestClient) -> None:
    assert acp_client.post("/runs", json={"agent_name": "nope", "input": []}).status_code == 404
    bad = acp_client.post(
        "/runs", content=b"not json", headers={"content-type": "application/json"}
    )
    assert bad.status_code == 400


def test_acp_token_middleware(report: Report) -> None:
    app = build_acp_app(
        report,
        models=canned_models(),
        registry=registry(),
        token="sekrit",  # noqa: S106
    )
    client = TestClient(app)
    assert client.get("/agents").status_code == 401
    assert client.get("/agents", headers={"Authorization": "Bearer sekrit"}).status_code == 200
    assert client.get("/agents", headers={"Authorization": "Bearer wrong"}).status_code == 401


# --------------------------------------------------------------------------- ACP interop
def test_registry_consumes_the_acp_facade(report: Report) -> None:
    """Our own remote-agent client can discover and run agents served by the facade."""
    app = build_acp_app(report, models=canned_models(), registry=registry())
    transport = httpx.ASGITransport(app=app)

    async def main() -> None:
        consumer = AgentRegistry()
        specs = await consumer.add_remote("http://127.0.0.1", transport=transport)
        assert {s.name for s in specs} == {"triage", "orchestrator"}
        triage = consumer.get("triage")
        assert triage.remote is not None
        assert triage.remote.protocol == "acp"
        result = await triage.remote.call("rank the threats")
        assert result["findings"][0]["priority"] == "P1"

    asyncio.run(main())


# --------------------------------------------------------------------------- both protocols
def test_both_protocols_on_one_port(report: Report) -> None:
    """The ``serve --protocol both`` composition: A2A at the root, ACP under /acp."""
    from starlette.routing import Mount

    acp_inner = build_acp_app(report, models=canned_models(), registry=registry())
    app = build_a2a_app(
        report,
        models=canned_models(),
        registry=registry(),
        base_url="http://testserver",
        extra_routes=[Mount("/acp", app=acp_inner)],
    )
    with TestClient(app) as client:
        card = client.get("/.well-known/agent-card.json").json()
        assert card["name"] == "startup-sbom-orchestrator"
        agents = client.get("/acp/agents").json()["agents"]
        assert {a["name"] for a in agents} == {"triage", "orchestrator"}


# --------------------------------------------------------------------------- binding guard
def test_require_token_for_non_loopback() -> None:
    require_token("127.0.0.1", None)
    require_token("localhost", None)
    require_token("::1", None)
    require_token("0.0.0.0", "token")  # noqa: S104 - explicit token makes it allowed
    with pytest.raises(AIConfigError, match="STARTUP_SBOM_AGENT_TOKEN"):
        require_token("0.0.0.0", None)  # noqa: S104
    assert is_loopback_host("[::1]")
    assert not is_loopback_host("example.org")
