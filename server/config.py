"""Server configuration settings"""
import os

# Server
HOST = os.getenv("SBOM_HOST", "0.0.0.0")
PORT = int(os.getenv("SBOM_PORT", 8000))

# Database
DATABASE_PATH = os.getenv("DATABASE_PATH", "database/sbom.db")
SCHEMA_PATH = os.getenv("SCHEMA_PATH", "database/schema.sql")

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-min-32-chars-long")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Agent settings
AGENT_HEARTBEAT_TIMEOUT_MINUTES = 5
