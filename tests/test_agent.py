import pytest
from unittest.mock import MagicMock, patch
from sbom_agent.service import SBOMAgent

# Mock Settings
@patch("sbom_agent.service.settings")
@patch("sbom_agent.service.SBOMAgent._detect_scanners")
def test_agent_initialization(mock_detect, mock_settings, monkeypatch):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    mock_settings.agent.poll_interval = 10
    # scanners config is now ignored/optional, detection is used
    mock_detect.return_value = ["apt", "docker"]
    
    agent = SBOMAgent()
    assert agent.agent_id == "test-agent"
    assert agent.server_url == "http://mock-server"
    assert "apt" in agent.enabled_scanners
    assert "docker" in agent.enabled_scanners

@patch("sbom_agent.service.settings")
@patch("sbom_agent.service.requests.request")
@patch("sbom_agent.service.SBOMAgent._detect_scanners")
def test_agent_register_success(mock_detect, mock_request, mock_settings):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    mock_settings.agent.hostname = "test-host"
    mock_detect.return_value = ["apt"]

    # Mock successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "registered"}
    mock_request.return_value = mock_response

    agent = SBOMAgent()
    success = agent.register()
    assert success is True
    mock_request.assert_called_once() 

@patch("sbom_agent.service.settings")
@patch("sbom_agent.service.subprocess.run")
@patch("sbom_agent.service.SBOMAgent._detect_scanners")
def test_scan_apt_packages(mock_detect, mock_subprocess, mock_settings):
    mock_settings.agent.id = "test-agent"
    mock_settings.agent.server_url = "http://mock-server"
    mock_detect.return_value = ["apt"]
    
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
    # Note: _detect_scanners is mocked, so we don't need to mock the 'which' calls for it.
    # But scan_apt_packages DOES call 'which dpkg-query' inside it.
    mock_subprocess.side_effect = [mock_which, mock_dpkg]

    agent = SBOMAgent()
    result = agent.scan_apt_packages()
    
    # We expect 2 packages
    assert result["total_count"] == 2
    assert result["packages"][0]["name"] == "package-a"
    assert result["packages"][1]["version"] == "2.0"
