import os
from sbom_core.config import load_config, SBOMConfig, ServerConfig, AgentConfig

def test_default_config():
    config = SBOMConfig()
    assert config.server.port == 8000
    assert config.agent.poll_interval == 30

def test_load_config_env(monkeypatch):
    # Mock file loading to return empty or specific dict if needed
    # Here we test structure integrity
    config = load_config()
    assert isinstance(config, SBOMConfig)
    assert isinstance(config.server, ServerConfig)
