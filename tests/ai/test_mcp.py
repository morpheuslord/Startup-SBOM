"""MCP server: tools, resources, prompts, and the --allow-scan gate for scan_target."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from startup_sbom.ai.mcp_server import build_server, validate_scan_target
from startup_sbom.models import Report

EXPECTED_TOOLS = {
    "get_summary",
    "list_threats",
    "get_threat",
    "explain_threat",
    "list_attack_chains",
    "get_attack_chain",
    "get_blast_radius",
    "list_supply_chain_findings",
    "get_package",
    "get_service",
    "get_intel",
    "get_fix_plan",
    "export_report",
}


def call(server: MCPServer, name: str, args: dict[str, Any]) -> Any:
    result = asyncio.run(server.call_tool(name, args))
    assert not result.is_error
    return result.structured_content


@pytest.fixture
def server(report: Report) -> MCPServer:
    return build_server(report)


def test_tool_inventory_without_allow_scan(server: MCPServer) -> None:
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == EXPECTED_TOOLS
    assert "scan_target" not in names  # refused by omission: no --allow-scan


def test_scan_target_refused_without_allow_list(server: MCPServer) -> None:
    with pytest.raises(ToolError, match="Unknown tool"):
        asyncio.run(server.call_tool("scan_target", {"target": "dir:/etc"}))


def test_scan_target_registered_with_allow_scan(report: Report, tmp_path: Path) -> None:
    gated = build_server(report, allow_scan=(tmp_path,))
    names = {t.name for t in asyncio.run(gated.list_tools())}
    assert "scan_target" in names


def test_validate_scan_target(tmp_path: Path) -> None:
    inside = tmp_path / "image"
    inside.mkdir()
    assert validate_scan_target(f"dir:{inside}", (tmp_path,)) == f"dir:{inside}"
    with pytest.raises(ValueError, match="outside the roots"):
        validate_scan_target("dir:/etc", (tmp_path,))
    with pytest.raises(ValueError, match="outside the roots"):
        validate_scan_target(f"dir:{tmp_path}/../escape", (tmp_path,))
    with pytest.raises(ValueError, match="not allowed over MCP"):
        validate_scan_target("docker:nginx", (tmp_path,))
    with pytest.raises(ValueError, match="not allowed over MCP"):
        validate_scan_target("host:/", (tmp_path,))
    with pytest.raises(ValueError, match="no path"):
        validate_scan_target("dir:", (tmp_path,))


def test_get_summary_and_threat_tools(server: MCPServer) -> None:
    summary = call(server, "get_summary", {})
    assert summary["summary"]["threats"] == 4
    assert summary["loaded_scans"][0]["scan_id"].startswith("7f1d1c5e")

    page = call(server, "list_threats", {"min_risk": 50, "limit": 2})
    assert page["total"] == 3
    assert len(page["items"]) == 2

    threat = call(server, "get_threat", {"threat_id": "TH-0001"})
    assert threat["threat"]["vulnerability"] == "CVE-2024-6387"

    explain = call(server, "explain_threat", {"threat_id": "TH-0001"})
    assert explain["risk_score"] == 92.5

    chains = call(server, "list_attack_chains", {"min_score": 80})
    assert [c["id"] for c in chains["items"]] == ["AC-0002"]
    chain = call(server, "get_attack_chain", {"chain_id": "AC-0001"})
    assert len(chain["steps"]) == 2

    blast = call(server, "get_blast_radius", {})
    assert blast["total"] == 1

    findings = call(server, "list_supply_chain_findings", {})
    assert findings["total"] == 2

    pkg = call(server, "get_package", {"query": "openssh"})
    assert pkg["matches"][0]["name"] == "openssh-server"
    svc = call(server, "get_service", {"query": "nginx"})
    assert svc["matches"][0]["network_exposed"] is True

    fix = call(server, "get_fix_plan", {})
    assert "remediations" in fix


def test_tool_errors_are_tool_errors(server: MCPServer) -> None:
    with pytest.raises(ToolError, match="unknown threat id"):
        asyncio.run(server.call_tool("get_threat", {"threat_id": "TH-9999"}))
    with pytest.raises(ToolError, match="unknown scan_id"):
        asyncio.run(server.call_tool("get_summary", {"scan_id": "nope"}))
    with pytest.raises(ToolError, match="only CVEs present"):
        asyncio.run(server.call_tool("get_intel", {"cve": "CVE-1999-0001"}))


def test_export_report_inline_and_capped(server: MCPServer) -> None:
    out = call(server, "export_report", {"format": "markdown"})
    assert out["format"] == "markdown"
    assert out["truncated"] is False
    assert "startup-sbom" in out["content"].lower() or "#" in out["content"]
    native = call(server, "export_report", {"format": "json"})
    parsed = json.loads(native["content"])
    assert parsed["metadata"]["scan_id"].startswith("7f1d1c5e")


def test_no_report_loaded_errors() -> None:
    empty = build_server(None, allow_scan=(Path("/tmp"),))
    with pytest.raises(ToolError, match="no report loaded"):
        asyncio.run(empty.call_tool("get_summary", {}))


def test_resources(server: MCPServer) -> None:
    contents = asyncio.run(server.read_resource("report://summary"))
    data = json.loads(next(iter(contents)).content)
    assert data["summary"]["threats"] == 4
    threat = asyncio.run(server.read_resource("report://threats/TH-0002"))
    parsed = json.loads(next(iter(threat)).content)
    assert parsed["threat"]["id"] == "TH-0002"


def test_prompts(server: MCPServer) -> None:
    prompts = {p.name for p in asyncio.run(server.list_prompts())}
    assert prompts == {"triage", "executive-summary"}
    triage = asyncio.run(server.get_prompt("triage"))
    assert "never invent CVEs" in triage.messages[0].content.text
    brief = asyncio.run(server.get_prompt("executive-summary"))
    assert "executive summary" in brief.messages[0].content.text
