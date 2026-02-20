"""
Fixtures and test configuration for SBOM Scanner tests.
"""
import os
import sys
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# ── Test config ────────────────────────────────────────────────
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"


@pytest.fixture(scope="session", autouse=True)
def setup_test_config():
    """Set up a temporary config for all tests"""
    config_content = """
server:
  host: "127.0.0.1"
  port: 8000
  db_path: ":memory:"
  output_dir: "{output_dir}"

agent:
  id: "test-agent"
  hostname: "test-host"
  server_url: "http://127.0.0.1:8000"
  poll_interval: 5
  output_dir: "{output_dir}"
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, "output")
        os.makedirs(output_dir, exist_ok=True)

        config_path = os.path.join(tmpdir, "test_sbom.conf")
        with open(config_path, "w") as f:
            f.write(config_content.format(output_dir=output_dir))

        os.environ["SBOM_CONFIG"] = config_path
        yield tmpdir


@pytest.fixture()
def test_db(tmp_path):
    """Create a fresh test database"""
    db_path = str(tmp_path / "test.db")

    if SCHEMA_PATH.exists():
        schema = SCHEMA_PATH.read_text()
    else:
        schema = """
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT UNIQUE NOT NULL,
            hostname TEXT, ip_address TEXT, os_info TEXT,
            status TEXT DEFAULT 'inactive',
            last_heartbeat DATETIME,
            registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            config_json TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            agent_id INTEGER REFERENCES agents(id),
            scan_type TEXT, target_path TEXT,
            status TEXT DEFAULT 'pending',
            started_at DATETIME, completed_at DATETIME,
            error_message TEXT, result_json TEXT
        );
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            name TEXT, version TEXT, package_manager TEXT,
            architecture TEXT, metadata_json TEXT
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            cve_id TEXT, severity TEXT, package_name TEXT,
            package_version TEXT, description TEXT,
            cvss_score TEXT, fixed_version TEXT
        );
        CREATE TABLE IF NOT EXISTS docker_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            image_name TEXT, tag TEXT,
            vulnerability_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS misconfigurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER REFERENCES scans(id),
            check_id TEXT, check_title TEXT,
            severity TEXT, status TEXT, resource TEXT,
            description TEXT, remediation TEXT, source TEXT
        );
        """

    conn = sqlite3.connect(db_path)
    conn.executescript(schema)
    conn.commit()
    conn.close()

    return db_path


@pytest.fixture()
def client(test_db, monkeypatch):
    """FastAPI TestClient with test database"""
    monkeypatch.setattr("sbom_core.config.settings.server.db_path", test_db)

    from fastapi.testclient import TestClient
    from sbom_server.main import app
    return TestClient(app)
