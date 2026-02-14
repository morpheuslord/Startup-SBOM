import os
import yaml
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    db_path: str = "data/sbom.db"

class AgentConfig(BaseModel):
    id: str = "agent-def"
    hostname: Optional[str] = None
    server_url: str = "http://localhost:8000"
    poll_interval: int = 30
    scanners: List[str] = ["apt", "docker"]

class SBOMConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    agent: AgentConfig = AgentConfig()

def load_config_data(env_var: str, default_paths: List[Path]) -> Dict[str, Any]:
    """Helper to load config from env var or list of paths"""
    path = os.getenv(env_var)
    if path and Path(path).exists():
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading config from {path}: {e}")
            return {}
            
    for p in default_paths:
        if p.exists():
            try:
                with open(p, "r") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Error loading config from {p}: {e}")
            return {}
    return {}

def load_config() -> SBOMConfig:
    base_dir = Path(__file__).resolve().parent.parent.parent
    
    # Load Server Config
    # 1. Check SBOM_SERVER_CONFIG
    # 2. Check config/server.conf, config/server.yaml
    # 3. Fallback to unified SBOM_CONFIG if specific not found? 
    #    Actually better to keep it simple: specific takes precedence.
    #    If specific file found, we assume it contains the fields directly.
    #    If unified found, we look for 'server' key.
    
    server_data = {}
    server_paths = [
        base_dir / "config" / "server.conf",
        base_dir / "config" / "server.yaml",
        Path("server.conf"),
        Path("server.yaml")
    ]
    
    dedicated_server = load_config_data("SBOM_SERVER_CONFIG", server_paths)
    if dedicated_server:
        # If loaded from server.conf, detailed fields are at root
        server_data = dedicated_server
    
    # Load Agent Config
    agent_data = {}
    agent_paths = [
        base_dir / "config" / "agent.conf",
        base_dir / "config" / "agent.yaml",
        Path("agent.conf"),
        Path("agent.yaml")
    ]
    
    dedicated_agent = load_config_data("SBOM_AGENT_CONFIG", agent_paths)
    if dedicated_agent:
        agent_data = dedicated_agent

    # Fallback to Unified Config if parts missing (e.g. for Tests using test_sbom.conf)
    # Tests usually set SBOM_CONFIG env var.
    unified_paths = [
        base_dir / "config" / "sbom.conf",
        base_dir / "config" / "sbom.yaml",
        Path("sbom.conf"),
        Path("sbom.yaml")
    ]
    unified = load_config_data("SBOM_CONFIG", unified_paths)
    
    if unified:
        if not server_data:
            server_data = unified.get("server", {})
        if not agent_data:
            agent_data = unified.get("agent", {})
            
    return SBOMConfig(
        server=ServerConfig(**server_data),
        agent=AgentConfig(**agent_data)
    )

# Global Instance
settings = load_config()
