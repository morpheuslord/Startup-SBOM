import os
import pytest
import sqlite3
from typing import Generator
from fastapi.testclient import TestClient

# Mock environment before importing config
TEST_DB = "test_sbom.db"
os.environ["SBOM_CONFIG"] = "config/test_sbom.conf"
os.environ["DATABASE_PATH"] = TEST_DB

from sbom_server.main import app
from sbom_server.database import get_db, init_database
from sbom_core.config import settings

@pytest.fixture(scope="session")
def db_engine():
    # Setup temp file DB
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass
    
    init_database()
    # Ensure it's accessible by closing any hold
    yield TEST_DB
    
    # Cleanup
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except PermissionError:
            pass

@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    monkeypatch.setattr(settings.server, "db_path", TEST_DB)
    monkeypatch.setattr(settings.server, "host", "localhost")
    monkeypatch.setattr(settings.server, "port", 8000)
    monkeypatch.setattr(settings.agent, "id", "test-agent")

@pytest.fixture
def client(db_engine) -> Generator:
    # Use standard TestClient with compatible httpx
    # Using context manager for lifespan events
    with TestClient(app) as c:
        yield c
