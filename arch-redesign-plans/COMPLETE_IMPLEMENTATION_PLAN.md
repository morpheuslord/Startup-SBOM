# SBOM Distributed Scanner - Complete Implementation Plan for AI Assistants

**Target:** Single developer using Cursor/Windsurf AI coding assistant
**Timeline:** 4 weeks, sequential implementation
**Stack:** Python FastAPI + SQLite + Vanilla JavaScript

---

## Project Overview

Build a distributed SBOM (Software Bill of Materials) scanner with:
- FastAPI backend with SQLite database
- Scanner agents that poll for work via HTTP
- Web interface using vanilla HTML/JS
- Support for APT, RPM, and Docker scanning with Trivy

**Architecture Principle:** Keep it simple. No React, no Redis, no Celery, no containers required.

---

## Phase 1: Project Setup & Database (Day 1)

### Step 1.1: Create Project Structure

```bash
mkdir sbom-scanner
cd sbom-scanner
mkdir -p server agent web database logs

# Create these empty files - we'll populate them next
touch server/__init__.py
touch server/main.py
touch server/database.py
touch server/config.py
touch agent/agent.py
touch agent/config.yaml
touch database/schema.sql
touch web/index.html
touch web/app.js
touch web/style.css
touch requirements.txt
touch README.md
```

**Final structure:**
```
sbom-scanner/
├── server/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── database.py          # Database helpers
│   └── config.py            # Configuration
├── agent/
│   ├── agent.py             # Scanner agent
│   └── config.yaml          # Agent config
├── web/
│   ├── index.html           # Dashboard
│   ├── app.js               # JavaScript
│   └── style.css            # Styling
├── database/
│   ├── schema.sql           # Database schema
│   └── sbom.db              # SQLite file (created on init)
├── logs/                    # Log files
├── requirements.txt         # Python dependencies
└── README.md
```

### Step 1.2: Create requirements.txt

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-multipart==0.0.9
pyyaml==6.0.1
requests==2.31.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
```

### Step 1.3: Create database/schema.sql

```sql
-- Database schema for SBOM Scanner
-- SQLite database with tables for agents, scans, packages, and vulnerabilities

CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    os_info TEXT,
    status TEXT DEFAULT 'inactive',
    last_heartbeat DATETIME,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    agent_id INTEGER REFERENCES agents(id),
    scan_type TEXT,
    target_path TEXT,
    status TEXT DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT,
    result_json TEXT
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    name TEXT,
    version TEXT,
    package_manager TEXT,
    architecture TEXT,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    cve_id TEXT,
    severity TEXT,
    package_name TEXT,
    package_version TEXT,
    description TEXT,
    cvss_score TEXT,
    fixed_version TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_scans_agent_id ON scans(agent_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
```

### Step 1.4: Create server/database.py

```python
"""Database connection and initialization"""
import sqlite3
import os
from pathlib import Path
from contextlib import contextmanager

DATABASE_PATH = "database/sbom.db"
SCHEMA_PATH = "database/schema.sql"

def init_database():
    """Initialize database with schema"""
    # Create database directory if it doesn't exist
    Path("database").mkdir(exist_ok=True)
    
    # Read schema
    with open(SCHEMA_PATH, 'r') as f:
        schema = f.read()
    
    # Create tables
    conn = sqlite3.connect(DATABASE_PATH)
    conn.executescript(schema)
    conn.commit()
    conn.close()
    
    print(f"Database initialized at {DATABASE_PATH}")

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    try:
        yield conn
    finally:
        conn.close()

def dict_from_row(row):
    """Convert sqlite3.Row to dict"""
    return {key: row[key] for key in row.keys()}
```

### Step 1.5: Create server/config.py

```python
"""Configuration settings"""
import os

# Server configuration
HOST = os.getenv("SBOM_HOST", "0.0.0.0")
PORT = int(os.getenv("SBOM_PORT", 8000))

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "database/sbom.db")

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-min-32-chars-long")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Agent settings
AGENT_HEARTBEAT_TIMEOUT_MINUTES = 5
```

### Step 1.6: Test Database Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from server.database import init_database; init_database()"

# Verify tables were created
sqlite3 database/sbom.db ".tables"
# Should output: agents packages scans vulnerabilities

# Check schema
sqlite3 database/sbom.db ".schema agents"
```

**Checkpoint:** You should have a working SQLite database with all tables created.

---

## Phase 2: FastAPI Server - Core Endpoints (Days 2-3)

### Step 2.1: Create server/main.py (Part 1: Setup & Health)

```python
"""
SBOM Scanner FastAPI Server
Single-file implementation with all endpoints
"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import asyncio
import json
import uvicorn
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from server.database import get_db, init_database, dict_from_row
from server.config import HOST, PORT

# Initialize FastAPI app
app = FastAPI(
    title="SBOM Scanner",
    description="Distributed SBOM scanning system",
    version="1.0.0"
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for web interface
app.mount("/static", StaticFiles(directory="web"), name="static")

# Global list for SSE connections
active_sse_connections: List[asyncio.Queue] = []

# ============ Startup/Shutdown Events ============

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    if not Path("database/sbom.db").exists():
        init_database()
    print(f"Server starting on http://{HOST}:{PORT}")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("Server shutting down...")

# ============ Root & Health Endpoints ============

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    try:
        with open("web/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>SBOM Scanner</h1><p>Web interface not found. Check web/ directory.</p>")

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }
```

### Step 2.2: Add Agent Management Endpoints

```python
# Add this to server/main.py after health_check

# ============ Agent Management ============

@app.post("/api/agents/register")
async def register_agent(agent_data: Dict[str, Any]):
    """Register or update an agent"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if agent exists
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (agent_data["agent_id"],)
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update existing agent
            cursor.execute("""
                UPDATE agents 
                SET hostname = ?, ip_address = ?, os_info = ?, 
                    status = 'active', last_heartbeat = ?
                WHERE agent_id = ?
            """, (
                agent_data.get("hostname"),
                agent_data.get("ip_address"),
                agent_data.get("os_info"),
                datetime.utcnow(),
                agent_data["agent_id"]
            ))
            message = "updated"
        else:
            # Insert new agent
            cursor.execute("""
                INSERT INTO agents (agent_id, hostname, ip_address, os_info, status, last_heartbeat)
                VALUES (?, ?, ?, ?, 'active', ?)
            """, (
                agent_data["agent_id"],
                agent_data.get("hostname"),
                agent_data.get("ip_address"),
                agent_data.get("os_info"),
                datetime.utcnow()
            ))
            message = "registered"
        
        conn.commit()
        
        return {
            "status": message,
            "agent_id": agent_data["agent_id"],
            "timestamp": datetime.utcnow().isoformat()
        }

@app.get("/api/agents")
async def list_agents():
    """List all registered agents"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT agent_id, hostname, ip_address, os_info, status, 
                   last_heartbeat, registered_at
            FROM agents
            ORDER BY registered_at DESC
        """)
        
        agents = []
        for row in cursor.fetchall():
            agent = dict_from_row(row)
            
            # Calculate if agent is stale
            if agent['last_heartbeat']:
                last_hb = datetime.fromisoformat(agent['last_heartbeat'])
                if datetime.utcnow() - last_hb > timedelta(minutes=5):
                    agent['status'] = 'inactive'
            
            agents.append(agent)
        
        return agents

@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: str):
    """Get specific agent details"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM agents WHERE agent_id = ?
        """, (agent_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return dict_from_row(row)

@app.post("/api/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str):
    """Record agent heartbeat"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE agents 
            SET last_heartbeat = ?, status = 'active' 
            WHERE agent_id = ?
        """, (datetime.utcnow(), agent_id))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        conn.commit()
        
        return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.delete("/api/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """Delete an agent"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        conn.commit()
        
        return {"status": "deleted", "agent_id": agent_id}
```

### Step 2.3: Add Scan Management Endpoints

```python
# Add this to server/main.py after agent endpoints

# ============ Scan Management ============

@app.post("/api/scans")
async def create_scan(scan_data: Dict[str, Any]):
    """Create a new scan record (called by agents)"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Generate scan ID
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{scan_data['agent_id']}"
        
        # Get agent database ID
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (scan_data['agent_id'],)
        )
        agent_row = cursor.fetchone()
        
        if not agent_row:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent_db_id = agent_row[0]
        
        # Create scan record
        cursor.execute("""
            INSERT INTO scans (scan_id, agent_id, scan_type, target_path, status, started_at)
            VALUES (?, ?, ?, ?, 'running', ?)
        """, (
            scan_id,
            agent_db_id,
            scan_data.get("scan_type", "unknown"),
            scan_data.get("target_path", "/"),
            datetime.utcnow()
        ))
        
        conn.commit()
        
        return {
            "scan_id": scan_id,
            "status": "created",
            "timestamp": datetime.utcnow().isoformat()
        }

@app.put("/api/scans/{scan_id}/results")
async def update_scan_results(
    scan_id: str,
    results: Dict[str, Any],
    background_tasks: BackgroundTasks
):
    """Update scan with results (called by agents)"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get scan database ID
        cursor.execute("SELECT id FROM scans WHERE scan_id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_db_id = scan_row[0]
        
        # Update scan status
        status = results.get("status", "completed")
        cursor.execute("""
            UPDATE scans 
            SET status = ?, 
                completed_at = ?,
                error_message = ?,
                result_json = ?
            WHERE scan_id = ?
        """, (
            status,
            datetime.utcnow() if status in ["completed", "failed"] else None,
            results.get("error_message"),
            json.dumps(results.get("data", {})),
            scan_id
        ))
        
        # Store packages if present
        if "packages" in results.get("data", {}):
            for pkg in results["data"]["packages"]:
                cursor.execute("""
                    INSERT INTO packages (scan_id, name, version, package_manager, architecture, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    scan_db_id,
                    pkg.get("name"),
                    pkg.get("version"),
                    pkg.get("package_manager"),
                    pkg.get("architecture"),
                    json.dumps(pkg.get("metadata", {}))
                ))
        
        # Store vulnerabilities if present
        if "vulnerabilities" in results.get("data", {}):
            for vuln in results["data"]["vulnerabilities"]:
                cursor.execute("""
                    INSERT INTO vulnerabilities 
                    (scan_id, cve_id, severity, package_name, package_version, description, cvss_score, fixed_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_db_id,
                    vuln.get("cve_id"),
                    vuln.get("severity"),
                    vuln.get("package_name"),
                    vuln.get("package_version"),
                    vuln.get("description", "")[:500],  # Limit description length
                    vuln.get("cvss_score"),
                    vuln.get("fixed_version")
                ))
        
        conn.commit()
        
        # Notify SSE clients
        background_tasks.add_task(
            notify_sse_clients,
            {"type": "scan_update", "scan_id": scan_id, "status": status}
        )
        
        return {"status": "updated", "scan_id": scan_id}

@app.get("/api/scans")
async def list_scans(
    limit: int = 50,
    status: Optional[str] = None,
    agent_id: Optional[str] = None
):
    """List scans with optional filters"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        query = """
            SELECT s.scan_id, s.scan_type, s.status, s.started_at, s.completed_at,
                   s.error_message, a.agent_id, a.hostname
            FROM scans s
            JOIN agents a ON s.agent_id = a.id
            WHERE 1=1
        """
        params = []
        
        if status:
            query += " AND s.status = ?"
            params.append(status)
        
        if agent_id:
            query += " AND a.agent_id = ?"
            params.append(agent_id)
        
        query += " ORDER BY s.started_at DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        scans = []
        for row in cursor.fetchall():
            scans.append(dict_from_row(row))
        
        return scans

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get detailed scan results including packages and vulnerabilities"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get scan info
        cursor.execute("""
            SELECT s.*, a.agent_id, a.hostname
            FROM scans s
            JOIN agents a ON s.agent_id = a.id
            WHERE s.scan_id = ?
        """, (scan_id,))
        
        scan_row = cursor.fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan = dict_from_row(scan_row)
        scan_db_id = scan['id']
        
        # Parse result_json if present
        if scan.get('result_json'):
            try:
                scan['results'] = json.loads(scan['result_json'])
            except:
                scan['results'] = {}
        
        # Get packages
        cursor.execute("""
            SELECT name, version, package_manager, architecture
            FROM packages
            WHERE scan_id = ?
            ORDER BY name
        """, (scan_db_id,))
        
        scan['packages'] = [dict_from_row(row) for row in cursor.fetchall()]
        
        # Get vulnerabilities grouped by severity
        cursor.execute("""
            SELECT cve_id, severity, package_name, package_version, 
                   description, cvss_score, fixed_version
            FROM vulnerabilities
            WHERE scan_id = ?
            ORDER BY 
                CASE severity 
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
        """, (scan_db_id,))
        
        scan['vulnerabilities'] = [dict_from_row(row) for row in cursor.fetchall()]
        
        # Add summary stats
        scan['stats'] = {
            'package_count': len(scan['packages']),
            'vulnerability_count': len(scan['vulnerabilities']),
            'critical_count': sum(1 for v in scan['vulnerabilities'] if v['severity'] == 'CRITICAL'),
            'high_count': sum(1 for v in scan['vulnerabilities'] if v['severity'] == 'HIGH'),
            'medium_count': sum(1 for v in scan['vulnerabilities'] if v['severity'] == 'MEDIUM'),
            'low_count': sum(1 for v in scan['vulnerabilities'] if v['severity'] == 'LOW'),
        }
        
        return scan

@app.post("/api/scans/trigger")
async def trigger_scan(trigger_data: Dict[str, Any]):
    """Queue a scan for an agent to pick up"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Verify agent exists
        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (trigger_data['agent_id'],)
        )
        agent_row = cursor.fetchone()
        
        if not agent_row:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent_db_id = agent_row[0]
        
        # Create pending scan
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{trigger_data['agent_id']}"
        
        cursor.execute("""
            INSERT INTO scans (scan_id, agent_id, scan_type, target_path, status)
            VALUES (?, ?, ?, ?, 'pending')
        """, (
            scan_id,
            agent_db_id,
            trigger_data.get('scan_type', 'apt'),
            trigger_data.get('target_path', '/')
        ))
        
        conn.commit()
        
        return {
            "scan_id": scan_id,
            "status": "pending",
            "message": "Scan queued for agent to pick up"
        }

@app.get("/api/agents/{agent_id}/pending-scans")
async def get_pending_scans(agent_id: str):
    """Get pending scans for a specific agent"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT s.scan_id, s.scan_type, s.target_path
            FROM scans s
            JOIN agents a ON s.agent_id = a.id
            WHERE a.agent_id = ? AND s.status = 'pending'
            ORDER BY s.id ASC
        """, (agent_id,))
        
        pending = []
        for row in cursor.fetchall():
            pending.append(dict_from_row(row))
        
        return pending
```

### Step 2.4: Add Statistics & SSE Endpoints

```python
# Add this to server/main.py after scan endpoints

# ============ Statistics ============

@app.get("/api/stats")
async def get_statistics():
    """Get dashboard statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        stats = {}
        
        # Total agents
        cursor.execute("SELECT COUNT(*) FROM agents")
        stats['total_agents'] = cursor.fetchone()[0]
        
        # Active agents (heartbeat within 5 minutes)
        cursor.execute("""
            SELECT COUNT(*) FROM agents 
            WHERE last_heartbeat > datetime('now', '-5 minutes')
        """)
        stats['active_agents'] = cursor.fetchone()[0]
        
        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        stats['total_scans'] = cursor.fetchone()[0]
        
        # Scans by status
        cursor.execute("""
            SELECT status, COUNT(*) 
            FROM scans 
            GROUP BY status
        """)
        stats['scans_by_status'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Total vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total_vulnerabilities'] = cursor.fetchone()[0]
        
        # Vulnerabilities by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM vulnerabilities 
            GROUP BY severity
        """)
        stats['vulnerabilities_by_severity'] = {
            row[0]: row[1] for row in cursor.fetchall()
        }
        
        # Recent activity
        cursor.execute("""
            SELECT COUNT(*) FROM scans 
            WHERE started_at > datetime('now', '-24 hours')
        """)
        stats['scans_last_24h'] = cursor.fetchone()[0]
        
        return stats

# ============ Server-Sent Events (SSE) ============

async def notify_sse_clients(message: Dict[str, Any]):
    """Send message to all connected SSE clients"""
    for queue in active_sse_connections:
        try:
            await queue.put(message)
        except:
            pass

@app.get("/api/events")
async def sse_endpoint():
    """Server-Sent Events endpoint for real-time updates"""
    async def event_generator():
        queue = asyncio.Queue()
        active_sse_connections.append(queue)
        
        try:
            while True:
                message = await queue.get()
                yield f"data: {json.dumps(message)}\n\n"
        except asyncio.CancelledError:
            active_sse_connections.remove(queue)
            raise
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )

# ============ Main Entry Point ============

if __name__ == "__main__":
    # Initialize database if needed
    if not Path("database/sbom.db").exists():
        init_database()
    
    # Run server
    uvicorn.run(
        "server.main:app",
        host=HOST,
        port=PORT,
        reload=True,  # Disable in production
        log_level="info"
    )
```

### Step 2.5: Test Server

```bash
# Start server
python server/main.py

# In another terminal, test endpoints:

# Health check
curl http://localhost:8000/api/health

# Stats (should return zeros since no data yet)
curl http://localhost:8000/api/stats

# Register a test agent
curl -X POST http://localhost:8000/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "hostname": "test-server",
    "ip_address": "127.0.0.1",
    "os_info": "Linux 5.15"
  }'

# List agents
curl http://localhost:8000/api/agents

# Trigger a scan
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-001",
    "scan_type": "apt"
  }'

# Check pending scans
curl http://localhost:8000/api/agents/test-agent-001/pending-scans
```

**Checkpoint:** Server should be running and responding to all API endpoints.

---

## Phase 3: Scanner Agent (Days 4-5)

### Step 3.1: Create agent/agent.py

```python
#!/usr/bin/env python3
"""
SBOM Scanner Agent
Polls server for work and executes scans
"""
import time
import yaml
import requests
import socket
import platform
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class SBOMAgent:
    def __init__(self, config_path: str):
        # Load configuration
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.agent_id = self.config['agent']['id']
        self.server_url = self.config['server']['url'].rstrip('/')
        self.poll_interval = self.config.get('poll_interval', 30)
        self.enabled_scanners = self.config.get('scanners', ['apt'])
        
        print(f"[{self._timestamp()}] SBOM Agent initialized")
        print(f"  Agent ID: {self.agent_id}")
        print(f"  Server: {self.server_url}")
        print(f"  Scanners: {', '.join(self.enabled_scanners)}")
    
    def _timestamp(self) -> str:
        """Get formatted timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request to server"""
        url = f"{self.server_url}{endpoint}"
        try:
            response = requests.request(method, url, timeout=10, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[{self._timestamp()}] Request failed: {e}")
            return None
    
    def get_system_info(self) -> Dict:
        """Collect system information"""
        return {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_info": platform.platform()
        }
    
    def register(self) -> bool:
        """Register with server"""
        result = self._make_request(
            'POST',
            '/api/agents/register',
            json=self.get_system_info()
        )
        
        if result:
            print(f"[{self._timestamp()}] Successfully registered with server")
            return True
        else:
            print(f"[{self._timestamp()}] Failed to register")
            return False
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        self._make_request('POST', f'/api/agents/{self.agent_id}/heartbeat')
    
    def check_for_work(self) -> List[Dict]:
        """Poll server for pending scans"""
        result = self._make_request(
            'GET',
            f'/api/agents/{self.agent_id}/pending-scans'
        )
        return result if result else []
    
    # ============ Scanners ============
    
    def scan_apt_packages(self) -> Dict:
        """Scan APT packages (Debian/Ubuntu)"""
        print(f"[{self._timestamp()}] Scanning APT packages...")
        packages = []
        
        try:
            # Check if dpkg is available
            result = subprocess.run(
                ['which', 'dpkg-query'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {
                    "error": "dpkg-query not found. Not a Debian-based system?",
                    "packages": []
                }
            
            # Get installed packages
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}|${Version}|${Architecture}\n'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2] if len(parts) > 2 else "unknown",
                        "package_manager": "apt"
                    })
            
            print(f"[{self._timestamp()}] Found {len(packages)} APT packages")
            
        except subprocess.CalledProcessError as e:
            return {
                "error": f"dpkg-query failed: {e}",
                "packages": []
            }
        except Exception as e:
            return {
                "error": str(e),
                "packages": []
            }
        
        return {
            "packages": packages,
            "total_count": len(packages)
        }
    
    def scan_rpm_packages(self) -> Dict:
        """Scan RPM packages (RHEL/CentOS/Fedora)"""
        print(f"[{self._timestamp()}] Scanning RPM packages...")
        packages = []
        
        try:
            # Check if rpm is available
            result = subprocess.run(
                ['which', 'rpm'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {
                    "error": "rpm not found. Not an RPM-based system?",
                    "packages": []
                }
            
            # Get installed packages
            result = subprocess.run(
                ['rpm', '-qa', '--queryformat', '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\n'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 2:
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "architecture": parts[2] if len(parts) > 2 else "unknown",
                        "package_manager": "rpm"
                    })
            
            print(f"[{self._timestamp()}] Found {len(packages)} RPM packages")
            
        except subprocess.CalledProcessError as e:
            return {
                "error": f"rpm command failed: {e}",
                "packages": []
            }
        except Exception as e:
            return {
                "error": str(e),
                "packages": []
            }
        
        return {
            "packages": packages,
            "total_count": len(packages)
        }
    
    def scan_docker_images(self) -> Dict:
        """Scan Docker images with Trivy"""
        print(f"[{self._timestamp()}] Scanning Docker images...")
        images = []
        vulnerabilities = []
        
        try:
            # Check if docker is available
            result = subprocess.run(
                ['which', 'docker'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {
                    "error": "Docker not found",
                    "images": [],
                    "vulnerabilities": []
                }
            
            # Check if trivy is available
            result = subprocess.run(
                ['which', 'trivy'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return {
                    "error": "Trivy not found. Install from https://aquasecurity.github.io/trivy/",
                    "images": [],
                    "vulnerabilities": []
                }
            
            # Get list of Docker images
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                capture_output=True,
                text=True,
                check=True
            )
            
            image_names = [
                line.strip() 
                for line in result.stdout.strip().split('\n') 
                if line and '<none>' not in line
            ]
            
            # Scan each image with Trivy
            for image_name in image_names:
                print(f"[{self._timestamp()}] Scanning {image_name}...")
                
                try:
                    trivy_result = subprocess.run(
                        ['trivy', 'image', '--format', 'json', '--quiet', image_name],
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout per image
                    )
                    
                    if trivy_result.returncode == 0:
                        trivy_data = json.loads(trivy_result.stdout)
                        
                        image_vulns = []
                        
                        # Extract vulnerabilities
                        for result_item in trivy_data.get('Results', []):
                            for vuln in result_item.get('Vulnerabilities', []):
                                image_vulns.append({
                                    "cve_id": vuln.get('VulnerabilityID'),
                                    "severity": vuln.get('Severity'),
                                    "package_name": vuln.get('PkgName'),
                                    "package_version": vuln.get('InstalledVersion'),
                                    "description": (vuln.get('Description', '') or vuln.get('Title', ''))[:200],
                                    "fixed_version": vuln.get('FixedVersion'),
                                    "cvss_score": self._extract_cvss(vuln)
                                })
                        
                        images.append({
                            "image": image_name,
                            "vulnerability_count": len(image_vulns)
                        })
                        
                        vulnerabilities.extend(image_vulns)
                        
                        print(f"[{self._timestamp()}] Found {len(image_vulns)} vulnerabilities in {image_name}")
                
                except subprocess.TimeoutExpired:
                    print(f"[{self._timestamp()}] Timeout scanning {image_name}")
                except Exception as e:
                    print(f"[{self._timestamp()}] Error scanning {image_name}: {e}")
            
        except subprocess.CalledProcessError as e:
            return {
                "error": f"Docker command failed: {e}",
                "images": [],
                "vulnerabilities": []
            }
        except Exception as e:
            return {
                "error": str(e),
                "images": [],
                "vulnerabilities": []
            }
        
        return {
            "images": images,
            "vulnerabilities": vulnerabilities,
            "total_images": len(images),
            "total_vulnerabilities": len(vulnerabilities)
        }
    
    def _extract_cvss(self, vuln: Dict) -> str:
        """Extract CVSS score from vulnerability data"""
        try:
            cvss = vuln.get('CVSS', {})
            for vendor, data in cvss.items():
                if isinstance(data, dict) and 'V3Score' in data:
                    return str(data['V3Score'])
            return "N/A"
        except:
            return "N/A"
    
    def perform_scan(self, scan_type: str) -> Dict:
        """Execute the appropriate scan"""
        if scan_type == "apt":
            return self.scan_apt_packages()
        elif scan_type == "rpm":
            return self.scan_rpm_packages()
        elif scan_type == "docker":
            return self.scan_docker_images()
        else:
            return {"error": f"Unknown scan type: {scan_type}"}
    
    def report_results(self, scan_id: str, status: str, data: Dict):
        """Send scan results back to server"""
        result = self._make_request(
            'PUT',
            f'/api/scans/{scan_id}/results',
            json={"status": status, "data": data}
        )
        
        if result:
            print(f"[{self._timestamp()}] Results uploaded for {scan_id}")
        else:
            print(f"[{self._timestamp()}] Failed to upload results")
    
    def run(self):
        """Main agent loop"""
        print(f"[{self._timestamp()}] Starting SBOM Agent...")
        
        # Register on startup
        if not self.register():
            print(f"[{self._timestamp()}] Failed to register. Exiting.")
            return
        
        heartbeat_counter = 0
        
        try:
            while True:
                # Send heartbeat every 5 polls
                if heartbeat_counter % 5 == 0:
                    self.send_heartbeat()
                heartbeat_counter += 1
                
                # Check for pending work
                pending_scans = self.check_for_work()
                
                for scan in pending_scans:
                    scan_id = scan['scan_id']
                    scan_type = scan['scan_type']
                    
                    print(f"[{self._timestamp()}] Processing scan: {scan_id} (type: {scan_type})")
                    
                    # Mark as running
                    self.report_results(scan_id, "running", {})
                    
                    # Perform the scan
                    try:
                        results = self.perform_scan(scan_type)
                        
                        if "error" in results:
                            self.report_results(scan_id, "failed", results)
                        else:
                            self.report_results(scan_id, "completed", results)
                    
                    except Exception as e:
                        print(f"[{self._timestamp()}] Scan failed: {e}")
                        self.report_results(
                            scan_id,
                            "failed",
                            {"error": str(e)}
                        )
                
                # Wait before next poll
                time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            print(f"\n[{self._timestamp()}] Shutting down...")
        except Exception as e:
            print(f"[{self._timestamp()}] Fatal error: {e}")
            raise

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent.py <config.yaml>")
        sys.exit(1)
    
    agent = SBOMAgent(sys.argv[1])
    agent.run()
```

### Step 3.2: Create agent/config.yaml

```yaml
agent:
  id: "agent-001"
  name: "Development Agent"

server:
  url: "http://localhost:8000"

# How often to poll for work (seconds)
poll_interval: 30

# Enabled scanners: apt, rpm, docker
scanners:
  - apt
  - docker
```

### Step 3.3: Test Agent

```bash
# Make agent executable
chmod +x agent/agent.py

# Start server in one terminal
python server/main.py

# Start agent in another terminal
python agent/agent.py agent/config.yaml

# In a third terminal, trigger a scan
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "scan_type": "apt"
  }'

# Watch agent logs - it should pick up and execute the scan

# Check results
curl http://localhost:8000/api/scans | jq
```

**Checkpoint:** Agent should register, poll for work, execute scans, and report results.

---

## Phase 4: Web Interface (Days 6-7)

### Step 4.1: Create web/index.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Scanner Dashboard</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <nav>
        <h1>🔍 SBOM Scanner</h1>
        <div class="nav-links">
            <a href="/" class="active">Dashboard</a>
            <a href="/static/agents.html">Agents</a>
            <a href="/static/scans.html">Scans</a>
        </div>
    </nav>

    <main>
        <!-- Statistics Cards -->
        <section class="stats">
            <div class="stat-card">
                <h3>Total Agents</h3>
                <p class="stat-value" id="total-agents">-</p>
                <p class="stat-sub" id="active-agents-sub">- active</p>
            </div>
            <div class="stat-card">
                <h3>Total Scans</h3>
                <p class="stat-value" id="total-scans">-</p>
            </div>
            <div class="stat-card">
                <h3>Completed Scans</h3>
                <p class="stat-value" id="completed-scans">-</p>
            </div>
            <div class="stat-card critical">
                <h3>Vulnerabilities</h3>
                <p class="stat-value" id="total-vulns">-</p>
                <p class="stat-sub" id="critical-vulns-sub">- critical</p>
            </div>
        </section>

        <!-- Recent Scans -->
        <section>
            <h2>Recent Scans</h2>
            <table id="recent-scans">
                <thead>
                    <tr>
                        <th>Scan ID</th>
                        <th>Agent</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Duration</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="7" class="loading">Loading...</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <!-- Trigger New Scan -->
        <section>
            <h2>Trigger New Scan</h2>
            <form id="trigger-form">
                <label>
                    Target Agent:
                    <select id="agent-select" required>
                        <option value="">Loading agents...</option>
                    </select>
                </label>
                
                <label>
                    Scan Type:
                    <select id="scan-type" required>
                        <option value="apt">APT Packages (Debian/Ubuntu)</option>
                        <option value="rpm">RPM Packages (RHEL/CentOS)</option>
                        <option value="docker">Docker Images (Trivy)</option>
                    </select>
                </label>
                
                <button type="submit">🚀 Trigger Scan</button>
            </form>
            
            <div id="trigger-status"></div>
        </section>
    </main>

    <footer>
        <p>SBOM Scanner v1.0 | Last updated: <span id="last-update">-</span></p>
    </footer>

    <script src="/static/app.js"></script>
</body>
</html>
```

### Step 4.2: Create web/app.js

```javascript
/**
 * SBOM Scanner - Frontend JavaScript
 * Vanilla JS implementation (no framework needed)
 */

// ============ Configuration ============

const API_BASE = '/api';
const REFRESH_INTERVAL = 30000; // 30 seconds

// ============ API Client ============

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error: ${endpoint}`, error);
        throw error;
    }
}

async function postAPI(endpoint, data) {
    return fetchAPI(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
}

// ============ Utility Functions ============

function formatTimestamp(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleString();
}

function formatDuration(startTime, endTime) {
    if (!startTime || !endTime) return '-';
    
    const start = new Date(startTime);
    const end = new Date(endTime);
    const diffMs = end - start;
    
    const seconds = Math.floor(diffMs / 1000);
    const minutes = Math.floor(seconds / 60);
    
    if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    }
    return `${seconds}s`;
}

function showMessage(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.textContent = message;
    element.className = `message ${type}`;
    element.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        element.style.display = 'none';
    }, 5000);
}

// ============ Dashboard Updates ============

async function updateStats() {
    try {
        const stats = await fetchAPI('/stats');
        
        // Update stat cards
        document.getElementById('total-agents').textContent = stats.total_agents || 0;
        document.getElementById('active-agents-sub').textContent = 
            `${stats.active_agents || 0} active`;
        
        document.getElementById('total-scans').textContent = stats.total_scans || 0;
        
        const completedScans = stats.scans_by_status?.completed || 0;
        document.getElementById('completed-scans').textContent = completedScans;
        
        document.getElementById('total-vulns').textContent = stats.total_vulnerabilities || 0;
        
        const criticalVulns = stats.vulnerabilities_by_severity?.CRITICAL || 0;
        document.getElementById('critical-vulns-sub').textContent = `${criticalVulns} critical`;
        
        // Update timestamp
        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        
    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

async function updateRecentScans() {
    try {
        const scans = await fetchAPI('/scans?limit=10');
        const tbody = document.querySelector('#recent-scans tbody');
        
        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty">No scans yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td class="mono">${scan.scan_id}</td>
                <td>${scan.hostname || scan.agent_id}</td>
                <td><span class="badge">${scan.scan_type.toUpperCase()}</span></td>
                <td><span class="status status-${scan.status}">${scan.status}</span></td>
                <td>${formatTimestamp(scan.started_at)}</td>
                <td>${formatDuration(scan.started_at, scan.completed_at)}</td>
                <td>
                    <a href="/static/scan-details.html?id=${scan.scan_id}" class="btn-small">View</a>
                </td>
            </tr>
        `).join('');
        
    } catch (error) {
        console.error('Failed to update scans:', error);
        const tbody = document.querySelector('#recent-scans tbody');
        tbody.innerHTML = '<tr><td colspan="7" class="error">Failed to load scans</td></tr>';
    }
}

async function loadAgents() {
    try {
        const agents = await fetchAPI('/agents');
        const select = document.getElementById('agent-select');
        
        if (!agents || agents.length === 0) {
            select.innerHTML = '<option value="">No agents registered</option>';
            select.disabled = true;
            return;
        }
        
        // Filter for active agents only
        const activeAgents = agents.filter(a => a.status === 'active');
        
        if (activeAgents.length === 0) {
            select.innerHTML = '<option value="">No active agents</option>';
            select.disabled = true;
            return;
        }
        
        select.innerHTML = activeAgents.map(agent => `
            <option value="${agent.agent_id}">
                ${agent.hostname || agent.agent_id}
            </option>
        `).join('');
        
        select.disabled = false;
        
    } catch (error) {
        console.error('Failed to load agents:', error);
        const select = document.getElementById('agent-select');
        select.innerHTML = '<option value="">Error loading agents</option>';
        select.disabled = true;
    }
}

// ============ Scan Triggering ============

async function handleTriggerScan(event) {
    event.preventDefault();
    
    const agentId = document.getElementById('agent-select').value;
    const scanType = document.getElementById('scan-type').value;
    
    if (!agentId) {
        showMessage('trigger-status', 'Please select an agent', 'error');
        return;
    }
    
    // Disable form during submission
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    
    submitBtn.disabled = true;
    submitBtn.textContent = '⏳ Triggering...';
    
    try {
        const result = await postAPI('/scans/trigger', {
            agent_id: agentId,
            scan_type: scanType
        });
        
        showMessage('trigger-status', 
            `✅ Scan triggered: ${result.scan_id}`, 
            'success'
        );
        
        // Refresh scans list after 2 seconds
        setTimeout(() => {
            updateRecentScans();
            updateStats();
        }, 2000);
        
    } catch (error) {
        showMessage('trigger-status', 
            `❌ Failed to trigger scan: ${error.message}`, 
            'error'
        );
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

// ============ Server-Sent Events ============

function connectSSE() {
    const eventSource = new EventSource('/api/events');
    
    eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            console.log('SSE Update:', data);
            
            // Refresh data when scans update
            if (data.type === 'scan_update') {
                updateRecentScans();
                updateStats();
            }
        } catch (error) {
            console.error('SSE parsing error:', error);
        }
    };
    
    eventSource.onerror = () => {
        console.error('SSE connection error');
        eventSource.close();
        
        // Reconnect after 5 seconds
        setTimeout(connectSSE, 5000);
    };
    
    console.log('SSE connected');
}

// ============ Initialization ============

document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the dashboard page
    if (document.getElementById('total-agents')) {
        console.log('Initializing dashboard...');
        
        // Initial load
        updateStats();
        updateRecentScans();
        loadAgents();
        
        // Connect to SSE for real-time updates
        connectSSE();
        
        // Periodic refresh (backup if SSE fails)
        setInterval(() => {
            updateStats();
            updateRecentScans();
        }, REFRESH_INTERVAL);
        
        // Setup form handler
        const form = document.getElementById('trigger-form');
        if (form) {
            form.addEventListener('submit', handleTriggerScan);
        }
    }
});
```

### Step 4.3: Create web/style.css

```css
/**
 * SBOM Scanner - Minimal CSS
 * Clean, professional styling without frameworks
 */

/* ============ Reset & Base ============ */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --color-primary: #2c3e50;
    --color-secondary: #3498db;
    --color-success: #27ae60;
    --color-warning: #f39c12;
    --color-danger: #e74c3c;
    --color-bg: #f5f6fa;
    --color-card: #ffffff;
    --color-text: #2c3e50;
    --color-text-light: #7f8c8d;
    --color-border: #dfe4ea;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: var(--color-text);
    background: var(--color-bg);
    font-size: 16px;
}

/* ============ Navigation ============ */

nav {
    background: var(--color-primary);
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

nav h1 {
    font-size: 1.5rem;
    font-weight: 600;
}

.nav-links {
    display: flex;
    gap: 1rem;
}

.nav-links a {
    color: white;
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    transition: background 0.2s;
}

.nav-links a:hover,
.nav-links a.active {
    background: rgba(255,255,255,0.1);
}

/* ============ Main Layout ============ */

main {
    max-width: 1400px;
    margin: 2rem auto;
    padding: 0 2rem;
}

section {
    background: var(--color-card);
    padding: 2rem;
    margin-bottom: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

h2 {
    margin-bottom: 1.5rem;
    color: var(--color-primary);
    font-size: 1.5rem;
    font-weight: 600;
}

/* ============ Statistics Cards ============ */

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    padding: 1.5rem;
}

.stat-card {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 2rem;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    transition: transform 0.2s;
}

.stat-card:hover {
    transform: translateY(-4px);
}

.stat-card h3 {
    font-size: 0.9rem;
    opacity: 0.9;
    margin-bottom: 0.5rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.stat-value {
    font-size: 3rem;
    font-weight: 700;
    margin: 0.5rem 0;
}

.stat-sub {
    font-size: 0.9rem;
    opacity: 0.8;
}

.stat-card:nth-child(2) {
    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
}

.stat-card:nth-child(3) {
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
}

.stat-card.critical {
    background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
}

/* ============ Tables ============ */

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.95rem;
}

th {
    background: var(--color-bg);
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    color: var(--color-text);
    border-bottom: 2px solid var(--color-border);
}

td {
    padding: 1rem;
    border-bottom: 1px solid var(--color-border);
}

tr:hover {
    background: var(--color-bg);
}

td.loading,
td.empty,
td.error {
    text-align: center;
    padding: 2rem;
    color: var(--color-text-light);
}

td.error {
    color: var(--color-danger);
}

.mono {
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
}

/* ============ Status Badges ============ */

.status {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    display: inline-block;
}

.status-pending {
    background: #fff3cd;
    color: #856404;
}

.status-running {
    background: #d1ecf1;
    color: #0c5460;
}

.status-completed {
    background: #d4edda;
    color: #155724;
}

.status-failed {
    background: #f8d7da;
    color: #721c24;
}

.badge {
    padding: 0.25rem 0.5rem;
    background: var(--color-secondary);
    color: white;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
}

/* ============ Forms ============ */

form {
    display: grid;
    gap: 1.5rem;
    max-width: 600px;
}

label {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-weight: 500;
    color: var(--color-text);
}

select,
input {
    padding: 0.75rem;
    border: 2px solid var(--color-border);
    border-radius: 6px;
    font-size: 1rem;
    transition: border-color 0.2s;
}

select:focus,
input:focus {
    outline: none;
    border-color: var(--color-secondary);
}

select:disabled {
    background: var(--color-bg);
    color: var(--color-text-light);
    cursor: not-allowed;
}

button {
    padding: 0.75rem 2rem;
    background: var(--color-secondary);
    color: white;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s, transform 0.1s;
}

button:hover {
    background: #2980b9;
    transform: translateY(-2px);
}

button:active {
    transform: translateY(0);
}

button:disabled {
    background: var(--color-text-light);
    cursor: not-allowed;
    transform: none;
}

.btn-small {
    padding: 0.5rem 1rem;
    background: var(--color-secondary);
    color: white;
    text-decoration: none;
    border-radius: 4px;
    font-size: 0.85rem;
    display: inline-block;
    transition: background 0.2s;
}

.btn-small:hover {
    background: #2980b9;
}

/* ============ Messages ============ */

.message {
    padding: 1rem;
    margin-top: 1rem;
    border-radius: 6px;
    display: none;
}

.message.info {
    background: #d1ecf1;
    color: #0c5460;
    border-left: 4px solid #17a2b8;
}

.message.success {
    background: #d4edda;
    color: #155724;
    border-left: 4px solid #28a745;
}

.message.error {
    background: #f8d7da;
    color: #721c24;
    border-left: 4px solid #dc3545;
}

/* ============ Footer ============ */

footer {
    text-align: center;
    padding: 2rem;
    color: var(--color-text-light);
    font-size: 0.9rem;
}

/* ============ Responsive ============ */

@media (max-width: 768px) {
    nav {
        flex-direction: column;
        gap: 1rem;
    }
    
    main {
        padding: 0 1rem;
    }
    
    .stats {
        grid-template-columns: 1fr;
    }
    
    table {
        font-size: 0.85rem;
    }
    
    th, td {
        padding: 0.75rem 0.5rem;
    }
}
```

### Step 4.4: Create Additional Pages (Optional)

Create `web/agents.html` and `web/scans.html` following the same pattern as `index.html`.

### Step 4.5: Test Web Interface

```bash
# Start server
python server/main.py

# Open browser to http://localhost:8000

# You should see:
# - Stats cards (will show 0s if no data)
# - Recent scans table
# - Trigger scan form

# Test the flow:
# 1. Start an agent
# 2. Trigger a scan from the web UI
# 3. Watch the scan appear in real-time
# 4. Click "View" to see scan details
```

**Checkpoint:** Full web interface should be functional with real-time updates.

---

## Phase 5: Testing & Documentation (Day 8)

### Step 5.1: Create README.md

```markdown
# SBOM Scanner

Distributed Software Bill of Materials (SBOM) scanning system.

## Features

- 🔍 Scan APT, RPM, and Docker packages
- 🔒 Trivy integration for vulnerability detection
- 📊 Web dashboard with real-time updates
- 🤖 Distributed agent architecture
- 💾 SQLite database (zero configuration)

## Quick Start

### Installation

bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from server.database import init_database; init_database()"


### Running

bash
# Terminal 1: Start server
python server/main.py

# Terminal 2: Start agent
python agent/agent.py agent/config.yaml

# Browser: Open http://localhost:8000


## Architecture

- **Server:** FastAPI with SQLite
- **Agent:** Python script that polls for work
- **Frontend:** Vanilla HTML/JS (no build required)
- **Real-time:** Server-Sent Events (SSE)

## Configuration

Edit `agent/config.yaml` to customize:
- Agent ID
- Server URL
- Poll interval
- Enabled scanners

## Requirements

- Python 3.8+
- Docker (optional, for container scanning)
- Trivy (optional, for vulnerability scanning)

## License

MIT
```

### Step 5.2: Create Test Script

Create `test.sh`:

```bash
#!/bin/bash

echo "=== SBOM Scanner Test Script ==="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test function
test_endpoint() {
    echo -n "Testing $1... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$2")
    
    if [ "$response" -eq 200 ]; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗ (HTTP $response)${NC}"
        return 1
    fi
}

# Check if server is running
if ! curl -s http://localhost:8000/api/health > /dev/null; then
    echo "❌ Server not running on port 8000"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Test endpoints
test_endpoint "Health check" "http://localhost:8000/api/health"
test_endpoint "Statistics" "http://localhost:8000/api/stats"
test_endpoint "List agents" "http://localhost:8000/api/agents"
test_endpoint "List scans" "http://localhost:8000/api/scans"

echo ""
echo "=== Test Complete ==="
```

```bash
chmod +x test.sh
./test.sh
```

---

## Phase 6: Production Deployment (Optional)

### Step 6.1: Create Systemd Services

See deployment section in the simplified architecture document.

### Step 6.2: Add Nginx Configuration

See deployment section for nginx.conf.

---

## Summary: Files to Create

This plan creates exactly **15 files**:

```
sbom-scanner/
├── server/
│   ├── __init__.py              (empty)
│   ├── main.py                  (~700 lines - ALL endpoints)
│   ├── database.py              (~50 lines)
│   └── config.py                (~20 lines)
├── agent/
│   ├── agent.py                 (~400 lines - ALL scanners)
│   └── config.yaml              (~15 lines)
├── web/
│   ├── index.html               (~150 lines)
│   ├── app.js                   (~300 lines)
│   └── style.css                (~400 lines)
├── database/
│   ├── schema.sql               (~80 lines)
│   └── sbom.db                  (created automatically)
├── requirements.txt             (7 packages)
├── README.md                    (documentation)
└── test.sh                      (test script)
```

**Total Lines of Code:** ~2,100 lines

---

## Implementation Checklist for AI Assistant

Use this checklist to track progress:

### Phase 1: Setup ✓
- [ ] Create project structure
- [ ] Create requirements.txt
- [ ] Create database schema
- [ ] Create database helper
- [ ] Create config file
- [ ] Test database initialization

### Phase 2: Server ✓
- [ ] Create FastAPI app skeleton
- [ ] Add health & root endpoints
- [ ] Add agent management endpoints
- [ ] Add scan management endpoints
- [ ] Add statistics endpoint
- [ ] Add SSE endpoint
- [ ] Test all API endpoints

### Phase 3: Agent ✓
- [ ] Create agent skeleton
- [ ] Add registration & heartbeat
- [ ] Add APT scanner
- [ ] Add RPM scanner
- [ ] Add Docker/Trivy scanner
- [ ] Add work polling
- [ ] Add result reporting
- [ ] Test agent end-to-end

### Phase 4: Web UI ✓
- [ ] Create HTML structure
- [ ] Create JavaScript logic
- [ ] Create CSS styling
- [ ] Add stats display
- [ ] Add scan list
- [ ] Add trigger form
- [ ] Add SSE connection
- [ ] Test web interface

### Phase 5: Testing ✓
- [ ] Create README
- [ ] Create test script
- [ ] Test full workflow
- [ ] Verify real-time updates

### Phase 6: Deploy (Optional)
- [ ] Create systemd services
- [ ] Setup nginx
- [ ] Configure firewall
- [ ] Test production setup

---

## Key Commands Reference

bash
# Setup
pip install -r requirements.txt
python -c "from server.database import init_database; init_database()"

# Run
python server/main.py                    # Start server
python agent/agent.py agent/config.yaml  # Start agent

# Test
curl http://localhost:8000/api/health    # Health check
curl http://localhost:8000/api/stats     # Statistics
./test.sh                                # Run all tests

# Database
sqlite3 database/sbom.db ".tables"       # List tables
sqlite3 database/sbom.db "SELECT * FROM agents;"  # View agents


---

## Success Criteria

At the end of implementation, you should be able to:

1. ✅ Start the server and access http://localhost:8000
2. ✅ Register an agent and see it in the dashboard
3. ✅ Trigger a scan from the web UI
4. ✅ Watch the agent pick up and execute the scan
5. ✅ See real-time updates in the dashboard
6. ✅ View scan results with packages and vulnerabilities
7. ✅ Have everything running on a single machine

**That's it!** This plan gives you a complete, working SBOM scanner in ~2100 lines of code that you can build, understand, and maintain solo.
