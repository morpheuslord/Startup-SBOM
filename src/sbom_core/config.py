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

def load_config() -> SBOMConfig:
    """
    Load configuration from:
    1. SBOM_CONFIG environment variable
    2. config/sbom.conf or config/sbom.yaml
    3. Default values
    """
    config_path = os.getenv("SBOM_CONFIG")
    
    if not config_path:
        # Check default locations
        base_dir = Path(__file__).resolve().parent.parent.parent
        candidates = [
            base_dir / "config" / "sbom.conf",
            base_dir / "config" / "sbom.yaml",
            Path("sbom.conf"),
            Path("sbom.yaml")
        ]
        for c in candidates:
            if c.exists():
                config_path = str(c)
                break
    
    config_data = {}
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading config from {config_path}: {e}")

    # Parse sections
    server_data = config_data.get("server", {})
    agent_data = config_data.get("agent", {})

    return SBOMConfig(
        server=ServerConfig(**server_data),
        agent=AgentConfig(**agent_data)
    )

# Global Instance
settings = load_config()
