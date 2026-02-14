import pytest
from unittest.mock import MagicMock, patch
from sbom_agent.agent import SBOMAgent

# Mock Settings
@patch("sbom_agent.agent.settings")
def test_agent_initialization(mock_settings, monkeypatch):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    mock_settings.agent.poll_interval = 10
    mock_settings.agent.scanners = ["apt"]
    
    agent = SBOMAgent()
    assert agent.agent_id == "test-agent"
    assert agent.server_url == "http://mock-server"

@patch("sbom_agent.agent.settings")
@patch("sbom_agent.agent.requests.request")
def test_agent_register_success(mock_request, mock_settings):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    mock_settings.agent.hostname = "test-host"

    # Mock successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "registered"}
    mock_request.return_value = mock_response

    agent = SBOMAgent()
    success = agent.register()
    assert success is True
    mock_request.assert_called_once() 

@patch("sbom_agent.agent.settings")
@patch("sbom_agent.agent.subprocess.run")
def test_scan_apt_packages(mock_subprocess, mock_settings):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    
    # Mock `which dpkg-query`
    mock_which = MagicMock()
    mock_which.returncode = 0
    
    # Mock `dpkg-query` output
    # The agent code splits by "\n" (newline), not literal "\n". 
    # Check agent.py: `result.stdout.strip().split("\n")`
    mock_dpkg = MagicMock()
    mock_dpkg.stdout = "package-a|1.0|amd64\npackage-b|2.0|all\n"
    mock_dpkg.returncode = 0
    
    # Side effect for sequential calls
    mock_subprocess.side_effect = [mock_which, mock_dpkg]

    agent = SBOMAgent()
    result = agent.scan_apt_packages()
    
    # We expect 2 packages
    assert result["total_count"] == 2
    assert result["packages"][0]["name"] == "package-a"
    assert result["packages"][1]["version"] == "2.0"
