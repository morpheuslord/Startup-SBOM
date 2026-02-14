from sbom_server.main import app

def test_read_main(client):
    response = client.get("/")
    assert response.status_code == 200
    # Should perform a loose check as HTML content might change
    assert "SBOM" in response.text or "Web interface not found" in response.text

def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_register_agent(client):
    agent_data = {
        "agent_id": "unit-test-agent",
        "hostname": "test-host",
        "ip_address": "127.0.0.1",
        "os_info": "Linux Test"
    }
    response = client.post("/api/agents/register", json=agent_data)
    assert response.status_code == 200
    assert response.json()["status"] in ["registered", "updated"]

def test_list_agents(client):
    response = client.get("/api/agents")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_create_scan(client):
    # Requires an agent first
    agent_data = {"agent_id": "scan-test-agent"}
    client.post("/api/agents/register", json=agent_data)
    
    scan_data = {
        "agent_id": "scan-test-agent",
        "scan_type": "apt",
        "target_path": "/"
    }
    response = client.post("/api/scans", json=scan_data)
    assert response.status_code == 200
    assert "scan_id" in response.json()
    return response.json()["scan_id"]

def test_update_scan_results(client):
    # We need to manually register and create scan here or rely on previous state (not recommended for unit tests)
    # Better to just re-run the creation logic helper or mock it.
    
    # Register agent
    agent_data = {"agent_id": "result-test-agent"}
    client.post("/api/agents/register", json=agent_data)

    # Create scan
    scan_data = {
        "agent_id": "result-test-agent",
        "scan_type": "apt",
        "target_path": "/"
    }
    create_res = client.post("/api/scans", json=scan_data)
    scan_id = create_res.json()["scan_id"]

    results = {
        "status": "completed",
        "data": {
            "packages": [
                {"name": "test-pkg", "version": "1.0", "package_manager": "apt"}
            ]
        }
    }
    response = client.put(f"/api/scans/{scan_id}/results", json=results)
    assert response.status_code == 200
    assert response.json()["status"] == "updated"
