"""
Tests for the SBOM Agent service.
"""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestAgentInit:
    @patch("sbom_agent.service.subprocess.run")
    def test_detect_scanners(self, mock_run):
        """Agent should detect available scanners via 'which' command"""
        # Make 'which' succeed for apt and docker, fail for others
        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "which" and cmd[1] in ("dpkg-query", "docker"):
                result.returncode = 0
            else:
                from subprocess import CalledProcessError
                raise CalledProcessError(1, cmd)
            return result

        mock_run.side_effect = side_effect

        from sbom_agent.service import SBOMAgent
        with patch.object(SBOMAgent, 'register', return_value=True):
            agent = SBOMAgent()
            assert "apt" in agent.enabled_scanners
            assert "docker" in agent.enabled_scanners
            assert "rpm" not in agent.enabled_scanners

    @patch("sbom_agent.service.subprocess.run")
    def test_agent_output_dir(self, mock_run):
        """Agent should create the output directory"""
        mock_run.side_effect = lambda *a, **kw: MagicMock(returncode=1)
        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        assert agent.output_dir.exists()


class TestAgentScanning:
    @patch("sbom_agent.service.subprocess.run")
    def test_scan_apt_packages(self, mock_run):
        """APT scan should parse dpkg-query output"""
        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "which" and cmd[1] == "dpkg-query":
                result.returncode = 0
                return result
            elif cmd[0] == "dpkg-query":
                result.returncode = 0
                result.stdout = "curl|7.68.0|amd64\nwget|1.20.3|amd64\n"
                return result
            result.returncode = 1
            return result

        mock_run.side_effect = side_effect

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        results = agent.scan_apt_packages()

        assert "packages" in results
        assert len(results["packages"]) == 2
        assert results["packages"][0]["name"] == "curl"
        assert results["packages"][0]["version"] == "7.68.0"
        assert results["packages"][0]["package_manager"] == "apt"

    @patch("sbom_agent.service.subprocess.run")
    def test_scan_apt_not_found(self, mock_run):
        """APT scan should return error when dpkg-query not found"""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        results = agent.scan_apt_packages()
        assert "error" in results

    @patch("sbom_agent.service.subprocess.run")
    def test_scan_docker_images(self, mock_run):
        """Docker scan should parse Trivy output correctly"""
        trivy_output = json.dumps({
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "Description": "Test vuln",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                        }
                    ],
                    "Misconfigurations": [],
                }
            ]
        })

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "which":
                result.returncode = 0
                return result
            elif cmd[0] == "docker" and cmd[1] == "images":
                result.returncode = 0
                result.stdout = "nginx:latest\n"
                return result
            elif cmd[0] == "trivy":
                result.returncode = 0
                result.stdout = trivy_output
                return result
            result.returncode = 1
            return result

        mock_run.side_effect = side_effect

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        results = agent.scan_docker_images()

        assert "images" in results
        assert len(results["images"]) == 1
        assert results["images"][0]["image_name"] == "nginx"
        assert results["images"][0]["tag"] == "latest"
        assert results["images"][0]["high_count"] == 1
        assert len(results["vulnerabilities"]) == 1
        assert results["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"

    @patch("sbom_agent.service.subprocess.run")
    def test_perform_scan_routing(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()

        # Unknown scan type
        result = agent.perform_scan("unknown-type")
        assert "error" in result


class TestAgentHelpers:
    @patch("sbom_agent.service.subprocess.run")
    def test_save_output(self, mock_run, tmp_path):
        """Output should be saved as JSON to the output directory"""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        agent.output_dir = tmp_path

        data = {"packages": [{"name": "test", "version": "1.0"}]}
        agent._save_output("apt", data)

        json_files = list(tmp_path.glob("apt_*.json"))
        assert len(json_files) == 1

        content = json.loads(json_files[0].read_text())
        assert content["packages"][0]["name"] == "test"

    @patch("sbom_agent.service.subprocess.run")
    def test_extract_cvss(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()

        vuln_with_cvss = {"CVSS": {"nvd": {"V3Score": 9.8}}}
        assert agent._extract_cvss(vuln_with_cvss) == "9.8"

        vuln_no_cvss = {}
        assert agent._extract_cvss(vuln_no_cvss) == "N/A"

    @patch("sbom_agent.service.subprocess.run")
    @patch("sbom_agent.service.requests.request")
    def test_register(self, mock_request, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "registered"}
        mock_request.return_value = mock_response

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        result = agent.register()
        assert result is True

    @patch("sbom_agent.service.subprocess.run")
    @patch("sbom_agent.service.requests.request")
    def test_register_failure(self, mock_request, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        import requests as req_lib
        mock_request.side_effect = req_lib.exceptions.ConnectionError("Connection refused")

        from sbom_agent.service import SBOMAgent
        agent = SBOMAgent()
        result = agent.register()
        assert result is False
