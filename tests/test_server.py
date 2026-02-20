"""
Tests for the SBOM Server API endpoints.
"""
import json
import pytest


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_root_route(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<title>SBOM Scanner" in resp.text


class TestAgentEndpoints:
    def test_register_agent(self, client):
        resp = client.post(
            "/api/agents/register",
            json={
                "agent_id": "test-agent-01",
                "hostname": "test-host",
                "ip_address": "192.168.1.1",
                "os_info": "Linux",
                "scanners": ["apt", "docker"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["agent_id"] == "test-agent-01"

    def test_register_agent_update(self, client):
        # First registration
        client.post(
            "/api/agents/register",
            json={"agent_id": "test-agent-02", "hostname": "host-a"},
        )
        # Second registration should update
        resp = client.post(
            "/api/agents/register",
            json={"agent_id": "test-agent-02", "hostname": "host-b"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "updated"

    def test_list_agents(self, client):
        client.post(
            "/api/agents/register",
            json={"agent_id": "list-agent", "hostname": "host-list"},
        )
        resp = client.get("/api/agents")
        assert resp.status_code == 200
        agents = resp.json()
        assert isinstance(agents, list)
        assert any(a["agent_id"] == "list-agent" for a in agents)

    def test_heartbeat(self, client):
        client.post(
            "/api/agents/register",
            json={"agent_id": "hb-agent", "hostname": "hb-host"},
        )
        resp = client.post("/api/agents/hb-agent/heartbeat")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_heartbeat_not_found(self, client):
        resp = client.post("/api/agents/nonexistent/heartbeat")
        assert resp.status_code == 404

    def test_delete_agent(self, client):
        client.post(
            "/api/agents/register",
            json={"agent_id": "del-agent", "hostname": "del-host"},
        )
        resp = client.delete("/api/agents/del-agent")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_delete_nonexistent(self, client):
        resp = client.delete("/api/agents/nonexistent")
        assert resp.status_code == 404


class TestScanEndpoints:
    def _register_and_trigger(self, client, agent_id="scan-agent", scan_type="apt"):
        client.post(
            "/api/agents/register",
            json={"agent_id": agent_id, "hostname": "scan-host"},
        )
        resp = client.post(
            "/api/scans/trigger",
            json={"agent_id": agent_id, "scan_type": scan_type},
        )
        return resp.json()

    def test_trigger_scan(self, client):
        result = self._register_and_trigger(client)
        assert result["status"] == "pending"
        assert "scan_id" in result

    def test_pending_scans(self, client):
        self._register_and_trigger(client, agent_id="pending-agent")
        resp = client.get("/api/agents/pending-agent/pending-scans")
        assert resp.status_code == 200
        scans = resp.json()
        assert isinstance(scans, list)
        assert len(scans) >= 1

    def test_update_scan_results_packages(self, client):
        trigger = self._register_and_trigger(client, agent_id="pkg-agent", scan_type="apt")
        scan_id = trigger["scan_id"]

        resp = client.put(
            f"/api/scans/{scan_id}/results",
            json={
                "status": "completed",
                "data": {
                    "packages": [
                        {"name": "curl", "version": "7.68.0", "package_manager": "apt", "architecture": "amd64"},
                        {"name": "wget", "version": "1.20.3", "package_manager": "apt", "architecture": "amd64"},
                    ],
                    "total_count": 2,
                },
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "updated"

    def test_update_scan_results_docker(self, client):
        trigger = self._register_and_trigger(client, agent_id="docker-agent", scan_type="docker")
        scan_id = trigger["scan_id"]

        resp = client.put(
            f"/api/scans/{scan_id}/results",
            json={
                "status": "completed",
                "data": {
                    "images": [
                        {
                            "image_name": "nginx",
                            "tag": "latest",
                            "vulnerability_count": 5,
                            "critical_count": 1,
                            "high_count": 2,
                            "medium_count": 1,
                            "low_count": 1,
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2024-1234",
                            "severity": "CRITICAL",
                            "package_name": "openssl",
                            "package_version": "1.1.1",
                            "description": "Buffer overflow",
                            "fixed_version": "1.1.2",
                            "cvss_score": "9.8",
                        }
                    ],
                    "total_images": 1,
                    "total_vulnerabilities": 1,
                },
            },
        )
        assert resp.status_code == 200

    def test_update_scan_results_misconfigs(self, client):
        trigger = self._register_and_trigger(client, agent_id="mc-agent", scan_type="prowler")
        scan_id = trigger["scan_id"]

        resp = client.put(
            f"/api/scans/{scan_id}/results",
            json={
                "status": "completed",
                "data": {
                    "misconfigurations": [
                        {
                            "check_id": "prowler-001",
                            "check_title": "Ensure root access is disabled",
                            "severity": "HIGH",
                            "status": "FAIL",
                            "resource": "/etc/ssh/sshd_config",
                            "description": "Root login is enabled",
                            "remediation": "Set PermitRootLogin no",
                            "source": "prowler",
                        }
                    ],
                    "total_misconfigurations": 1,
                },
            },
        )
        assert resp.status_code == 200

    def test_list_scans(self, client):
        self._register_and_trigger(client, agent_id="list-scan-agent")
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_scan_details(self, client):
        trigger = self._register_and_trigger(client, agent_id="detail-agent")
        scan_id = trigger["scan_id"]
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == scan_id
        assert "stats" in data


class TestDataEndpoints:
    def _setup_docker_data(self, client):
        client.post(
            "/api/agents/register",
            json={"agent_id": "data-agent", "hostname": "data-host"},
        )
        trigger = client.post(
            "/api/scans/trigger",
            json={"agent_id": "data-agent", "scan_type": "docker"},
        ).json()

        client.put(
            f"/api/scans/{trigger['scan_id']}/results",
            json={
                "status": "completed",
                "data": {
                    "images": [
                        {
                            "image_name": "alpine",
                            "tag": "3.18",
                            "vulnerability_count": 2,
                            "critical_count": 0,
                            "high_count": 1,
                            "medium_count": 1,
                            "low_count": 0,
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "cve_id": "CVE-2024-5555",
                            "severity": "HIGH",
                            "package_name": "busybox",
                            "package_version": "1.35",
                            "description": "Path traversal",
                            "cvss_score": "7.5",
                        }
                    ],
                    "misconfigurations": [
                        {
                            "check_id": "DS001",
                            "check_title": "root user",
                            "severity": "MEDIUM",
                            "status": "FAIL",
                            "resource": "Dockerfile",
                            "source": "trivy",
                        }
                    ],
                },
            },
        )

    def test_list_docker_images(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/docker-images")
        assert resp.status_code == 200
        images = resp.json()
        assert isinstance(images, list)
        assert any(i["image_name"] == "alpine" for i in images)

    def test_list_vulnerabilities(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/vulnerabilities")
        assert resp.status_code == 200
        vulns = resp.json()
        assert isinstance(vulns, list)

    def test_vulnerabilities_filter(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/vulnerabilities?severity=HIGH")
        assert resp.status_code == 200

    def test_vulnerabilities_search(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/vulnerabilities?search=busybox")
        assert resp.status_code == 200

    def test_list_misconfigurations(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/misconfigurations")
        assert resp.status_code == 200
        mcs = resp.json()
        assert isinstance(mcs, list)

    def test_misconfigurations_filter(self, client):
        self._setup_docker_data(client)
        resp = client.get("/api/misconfigurations?severity=MEDIUM&status=FAIL")
        assert resp.status_code == 200


class TestStatistics:
    def test_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_agents" in data
        assert "total_scans" in data
        assert "total_vulnerabilities" in data
        assert "total_misconfigurations" in data
        assert "total_docker_images" in data
        assert "vulnerabilities_by_severity" in data
        assert "misconfigs_by_severity" in data
        assert "scans_by_type" in data
