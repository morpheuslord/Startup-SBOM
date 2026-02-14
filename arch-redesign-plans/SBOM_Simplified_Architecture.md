# SBOM Distributed Scanning System - Simplified Architecture for Solo Developers

**Philosophy: Keep It Simple, Ship Fast**

Based on the 2025 architectural refinement principles, this guide prioritizes:
- ✅ **Implementability over elegance** - No premature abstraction
- ✅ **Single developer maintainability** - No complex orchestration
- ✅ **Progressive enhancement** - Start simple, add complexity only when needed
- ✅ **The Rule of Three** - Don't abstract until you've duplicated code 3+ times

## Technology Stack (Solo Developer Edition)

### Backend
- **API Framework:** FastAPI (Python) - simple, fast, well-documented
- **Database:** SQLite - zero configuration, file-based, perfect for single server
- **Background Jobs:** FastAPI BackgroundTasks - built-in, no external dependencies
- **Authentication:** Simple JWT with python-jose - no OAuth complexity
- **Real-time Updates:** Server-Sent Events (SSE) - simpler than WebSockets

### Frontend
- **HTML + Vanilla JavaScript** - No build step required
- **Styling:** Minimal CSS or CDN-based framework (e.g., PicoCSS, Water.css)
- **HTTP Client:** Native fetch API - no axios needed
- **Optional:** HTMX for dynamic updates without JavaScript complexity

### Scanner Agents
- **Language:** Python (same as server)
- **Communication:** Simple HTTP polling - no persistent connections
- **Configuration:** Single YAML file
- **Trivy:** CLI integration for container scanning

### Deployment
- **Single VPS** or local machine
- **Systemd services** for process management
- **Nginx** for reverse proxy (optional)
- **No Docker required** (but optional for Trivy)

---

## System Architecture (Simplified)

```
┌─────────────────────────────────────┐
│   Web Interface (HTML + JS)        │
│   Served by FastAPI StaticFiles     │
└──────────────┬──────────────────────┘
               │ HTTP REST
┌──────────────▼──────────────────────┐
│   FastAPI Server                    │
│   - REST API endpoints              │
│   - Background tasks (no Celery!)   │
│   - SSE for real-time updates       │
│   - SQLite database                 │
└──────────────┬──────────────────────┘
               │ HTTP Polling (every 30s)
    ┌──────────┼──────────┐
    │          │          │
┌───▼───┐  ┌──▼───┐  ┌──▼───┐
│Agent 1│  │Agent2│  │Agent3│
│(Python│  │      │  │      │
│script)│  │      │  │      │
└───────┘  └──────┘  └──────┘
```

**Key Simplifications:**
- No Redis, no Celery, no message brokers
- No WebSockets - just SSE for push updates
- Agents poll the server via HTTP (stateless)
- Everything runs as simple Python processes
- Single SQLite file for all data

---

## Database Schema (SQLite)

```sql
-- agents.sql

CREATE TABLE agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    os_info TEXT,
    status TEXT DEFAULT 'inactive',
    last_heartbeat DATETIME,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    config_json TEXT -- Store config as JSON string
);

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    agent_id INTEGER REFERENCES agents(id),
    scan_type TEXT,
    target_path TEXT,
    status TEXT DEFAULT 'pending',
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT,
    result_json TEXT -- Store results as JSON string
);

CREATE TABLE packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    name TEXT,
    version TEXT,
    package_manager TEXT,
    architecture TEXT,
    metadata_json TEXT
);

CREATE TABLE vulnerabilities (
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

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_agents_agent_id ON agents(agent_id);
CREATE INDEX idx_scans_agent_id ON scans(agent_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
```

---

## Project Structure (Minimal)

```
sbom-simple/
├── server/
│   ├── main.py              # FastAPI app
│   ├── database.py          # SQLite connection
│   ├── models.py            # Data models
│   ├── auth.py              # Simple JWT auth
│   ├── api_agents.py        # Agent endpoints
│   ├── api_scans.py         # Scan endpoints
│   └── config.py            # Configuration
│
├── agent/
│   ├── agent.py             # Main agent script
│   ├── scanners.py          # Scanner implementations
│   ├── config.yaml          # Agent configuration
│   └── requirements.txt
│
├── web/
│   ├── index.html           # Dashboard
│   ├── agents.html          # Agent list
│   ├── scans.html           # Scan results
│   ├── style.css            # Simple styling
│   └── app.js               # Vanilla JavaScript
│
├── database/
│   └── sbom.db              # SQLite database file
│
├── requirements.txt         # Python dependencies
├── setup.sh                 # Installation script
└── README.md
```

---

## Implementation Guide

### Phase 1: Basic Server (Week 1)

**File: `server/main.py`**

```python
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3
import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, List
import uvicorn

app = FastAPI(title="SBOM Scanner")

# Mount static files for web interface
app.mount("/static", StaticFiles(directory="web"), name="static")

# Database connection
def get_db():
    conn = sqlite3.connect('database/sbom.db')
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Simple in-memory event stream for SSE
active_connections = []

# ============ API Endpoints ============

@app.get("/")
async def root():
    with open("web/index.html") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ============ Agent Management ============

@app.post("/api/agents/register")
async def register_agent(
    agent_data: dict,
    db: sqlite3.Connection = Depends(get_db)
):
    """Register or update an agent"""
    cursor = db.cursor()
    
    # Check if agent exists
    cursor.execute(
        "SELECT id FROM agents WHERE agent_id = ?",
        (agent_data["agent_id"],)
    )
    existing = cursor.fetchone()
    
    if existing:
        # Update existing
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
    else:
        # Insert new
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
    
    db.commit()
    return {"status": "registered", "agent_id": agent_data["agent_id"]}

@app.get("/api/agents")
async def list_agents(db: sqlite3.Connection = Depends(get_db)):
    """List all agents"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT agent_id, hostname, ip_address, os_info, status, 
               last_heartbeat, registered_at
        FROM agents
        ORDER BY registered_at DESC
    """)
    
    agents = []
    for row in cursor.fetchall():
        agents.append(dict(row))
    
    return agents

@app.post("/api/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    db: sqlite3.Connection = Depends(get_db)
):
    """Record agent heartbeat"""
    cursor = db.cursor()
    cursor.execute(
        "UPDATE agents SET last_heartbeat = ?, status = 'active' WHERE agent_id = ?",
        (datetime.utcnow(), agent_id)
    )
    db.commit()
    
    return {"status": "ok"}

# ============ Scan Management ============

@app.post("/api/scans")
async def create_scan(
    scan_data: dict,
    db: sqlite3.Connection = Depends(get_db)
):
    """Create a new scan record"""
    cursor = db.cursor()
    
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{scan_data['agent_id']}"
    
    cursor.execute("""
        INSERT INTO scans (scan_id, agent_id, scan_type, target_path, status, started_at)
        VALUES (?, 
                (SELECT id FROM agents WHERE agent_id = ?),
                ?, ?, 'running', ?)
    """, (
        scan_id,
        scan_data["agent_id"],
        scan_data["scan_type"],
        scan_data.get("target_path", "/"),
        datetime.utcnow()
    ))
    
    db.commit()
    
    return {"scan_id": scan_id, "status": "created"}

@app.put("/api/scans/{scan_id}/results")
async def update_scan_results(
    scan_id: str,
    results: dict,
    background_tasks: BackgroundTasks,
    db: sqlite3.Connection = Depends(get_db)
):
    """Update scan with results"""
    cursor = db.cursor()
    
    cursor.execute("""
        UPDATE scans 
        SET status = ?, completed_at = ?, result_json = ?
        WHERE scan_id = ?
    """, (
        results.get("status", "completed"),
        datetime.utcnow() if results.get("status") == "completed" else None,
        json.dumps(results.get("data", {})),
        scan_id
    ))
    
    # Store packages
    if "packages" in results.get("data", {}):
        scan_db_id = cursor.execute(
            "SELECT id FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
        
        for pkg in results["data"]["packages"]:
            cursor.execute("""
                INSERT INTO packages (scan_id, name, version, package_manager, architecture)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_db_id,
                pkg.get("name"),
                pkg.get("version"),
                pkg.get("package_manager"),
                pkg.get("architecture")
            ))
    
    # Store vulnerabilities
    if "vulnerabilities" in results.get("data", {}):
        scan_db_id = cursor.execute(
            "SELECT id FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]
        
        for vuln in results["data"]["vulnerabilities"]:
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (scan_id, cve_id, severity, package_name, package_version, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_db_id,
                vuln.get("cve_id"),
                vuln.get("severity"),
                vuln.get("package_name"),
                vuln.get("package_version"),
                vuln.get("description")
            ))
    
    db.commit()
    
    # Notify connected clients via SSE
    background_tasks.add_task(notify_clients, {
        "type": "scan_complete",
        "scan_id": scan_id
    })
    
    return {"status": "updated"}

@app.get("/api/scans")
async def list_scans(
    limit: int = 50,
    db: sqlite3.Connection = Depends(get_db)
):
    """List recent scans"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT s.scan_id, s.scan_type, s.status, s.started_at, s.completed_at,
               a.agent_id, a.hostname
        FROM scans s
        JOIN agents a ON s.agent_id = a.id
        ORDER BY s.started_at DESC
        LIMIT ?
    """, (limit,))
    
    scans = []
    for row in cursor.fetchall():
        scans.append(dict(row))
    
    return scans

@app.get("/api/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    db: sqlite3.Connection = Depends(get_db)
):
    """Get detailed scan results"""
    cursor = db.cursor()
    
    # Get scan info
    cursor.execute("""
        SELECT s.*, a.agent_id, a.hostname
        FROM scans s
        JOIN agents a ON s.agent_id = a.id
        WHERE s.scan_id = ?
    """, (scan_id,))
    
    scan = cursor.fetchone()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_dict = dict(scan)
    
    # Get packages
    cursor.execute("""
        SELECT name, version, package_manager, architecture
        FROM packages
        WHERE scan_id = ?
    """, (scan_dict["id"],))
    scan_dict["packages"] = [dict(row) for row in cursor.fetchall()]
    
    # Get vulnerabilities
    cursor.execute("""
        SELECT cve_id, severity, package_name, package_version, description
        FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY 
            CASE severity 
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END
    """, (scan_dict["id"],))
    scan_dict["vulnerabilities"] = [dict(row) for row in cursor.fetchall()]
    
    return scan_dict

# ============ Scan Triggering ============

@app.post("/api/scans/trigger")
async def trigger_scan(
    trigger_data: dict,
    db: sqlite3.Connection = Depends(get_db)
):
    """Queue a scan for an agent to pick up"""
    cursor = db.cursor()
    
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{trigger_data['agent_id']}"
    
    cursor.execute("""
        INSERT INTO scans (scan_id, agent_id, scan_type, status)
        VALUES (?, 
                (SELECT id FROM agents WHERE agent_id = ?),
                ?, 'pending')
    """, (
        scan_id,
        trigger_data["agent_id"],
        trigger_data["scan_type"]
    ))
    
    db.commit()
    
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Scan queued for agent"
    }

@app.get("/api/agents/{agent_id}/pending-scans")
async def get_pending_scans(
    agent_id: str,
    db: sqlite3.Connection = Depends(get_db)
):
    """Get scans waiting for this agent"""
    cursor = db.cursor()
    cursor.execute("""
        SELECT scan_id, scan_type, target_path
        FROM scans
        WHERE agent_id = (SELECT id FROM agents WHERE agent_id = ?)
        AND status = 'pending'
    """, (agent_id,))
    
    return [dict(row) for row in cursor.fetchall()]

# ============ Server-Sent Events for Real-time Updates ============

async def notify_clients(message: dict):
    """Send message to all connected SSE clients"""
    for queue in active_connections:
        await queue.put(message)

@app.get("/api/events")
async def events():
    """SSE endpoint for real-time updates"""
    async def event_stream():
        queue = asyncio.Queue()
        active_connections.append(queue)
        
        try:
            while True:
                message = await queue.get()
                yield f"data: {json.dumps(message)}\n\n"
        except asyncio.CancelledError:
            active_connections.remove(queue)
    
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream"
    )

# ============ Statistics ============

@app.get("/api/stats")
async def get_stats(db: sqlite3.Connection = Depends(get_db)):
    """Get dashboard statistics"""
    cursor = db.cursor()
    
    stats = {}
    
    # Total agents
    cursor.execute("SELECT COUNT(*) FROM agents")
    stats["total_agents"] = cursor.fetchone()[0]
    
    # Active agents (heartbeat in last 5 minutes)
    cursor.execute("""
        SELECT COUNT(*) FROM agents 
        WHERE last_heartbeat > datetime('now', '-5 minutes')
    """)
    stats["active_agents"] = cursor.fetchone()[0]
    
    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scans")
    stats["total_scans"] = cursor.fetchone()[0]
    
    # Active scans
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
    stats["active_scans"] = cursor.fetchone()[0]
    
    # Total vulnerabilities
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    stats["total_vulnerabilities"] = cursor.fetchone()[0]
    
    # Vulnerabilities by severity
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY severity
    """)
    stats["vulnerabilities_by_severity"] = {
        row[0]: row[1] for row in cursor.fetchall()
    }
    
    return stats

if __name__ == "__main__":
    # Initialize database
    conn = sqlite3.connect('database/sbom.db')
    with open('database/schema.sql') as f:
        conn.executescript(f.read())
    conn.close()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

### Phase 2: Scanner Agent (Week 2)

**File: `agent/agent.py`**

```python
#!/usr/bin/env python3
"""
Simple SBOM Scanner Agent - Polls server for work
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
from typing import Dict, List

class SBOMAgent:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.agent_id = self.config['agent']['id']
        self.server_url = self.config['server']['url']
        self.poll_interval = self.config.get('poll_interval', 30)
        
    def get_system_info(self) -> Dict:
        """Collect system information"""
        return {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_info": platform.platform()
        }
    
    def register(self):
        """Register with server"""
        try:
            response = requests.post(
                f"{self.server_url}/api/agents/register",
                json=self.get_system_info(),
                timeout=10
            )
            response.raise_for_status()
            print(f"[{datetime.now()}] Registered with server")
        except Exception as e:
            print(f"[{datetime.now()}] Registration failed: {e}")
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            requests.post(
                f"{self.server_url}/api/agents/{self.agent_id}/heartbeat",
                timeout=5
            )
        except Exception as e:
            print(f"[{datetime.now()}] Heartbeat failed: {e}")
    
    def check_for_work(self) -> List[Dict]:
        """Poll server for pending scans"""
        try:
            response = requests.get(
                f"{self.server_url}/api/agents/{self.agent_id}/pending-scans",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[{datetime.now()}] Failed to check for work: {e}")
            return []
    
    def scan_apt_packages(self) -> Dict:
        """Scan APT packages (Debian/Ubuntu)"""
        packages = []
        
        try:
            # Use dpkg-query to list installed packages
            result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}|${Version}|${Architecture}\\n'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "architecture": parts[2] if len(parts) > 2 else "unknown",
                            "package_manager": "apt"
                        })
        
        except Exception as e:
            print(f"Error scanning APT packages: {e}")
        
        return {"packages": packages, "total_count": len(packages)}
    
    def scan_rpm_packages(self) -> Dict:
        """Scan RPM packages (RHEL/CentOS/Fedora)"""
        packages = []
        
        try:
            result = subprocess.run(
                ['rpm', '-qa', '--queryformat', '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\\n'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "architecture": parts[2] if len(parts) > 2 else "unknown",
                            "package_manager": "rpm"
                        })
        
        except Exception as e:
            print(f"Error scanning RPM packages: {e}")
        
        return {"packages": packages, "total_count": len(packages)}
    
    def scan_docker_images(self) -> Dict:
        """Scan Docker images with Trivy"""
        images = []
        vulnerabilities = []
        
        try:
            # List Docker images
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for image_name in result.stdout.strip().split('\n'):
                if image_name and image_name != '<none>:<none>':
                    # Run Trivy scan
                    trivy_result = subprocess.run(
                        ['trivy', 'image', '--format', 'json', '--quiet', image_name],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if trivy_result.returncode == 0:
                        trivy_data = json.loads(trivy_result.stdout)
                        
                        # Extract vulnerabilities
                        for result_item in trivy_data.get('Results', []):
                            for vuln in result_item.get('Vulnerabilities', []):
                                vulnerabilities.append({
                                    "cve_id": vuln.get('VulnerabilityID'),
                                    "severity": vuln.get('Severity'),
                                    "package_name": vuln.get('PkgName'),
                                    "package_version": vuln.get('InstalledVersion'),
                                    "description": vuln.get('Description', '')[:200],
                                    "fixed_version": vuln.get('FixedVersion')
                                })
                        
                        images.append({
                            "image": image_name,
                            "vulnerability_count": len(vulnerabilities)
                        })
        
        except Exception as e:
            print(f"Error scanning Docker images: {e}")
        
        return {
            "images": images,
            "vulnerabilities": vulnerabilities,
            "total_images": len(images),
            "total_vulnerabilities": len(vulnerabilities)
        }
    
    def perform_scan(self, scan_type: str) -> Dict:
        """Execute the appropriate scan"""
        print(f"[{datetime.now()}] Starting {scan_type} scan...")
        
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
        try:
            response = requests.put(
                f"{self.server_url}/api/scans/{scan_id}/results",
                json={"status": status, "data": data},
                timeout=30
            )
            response.raise_for_status()
            print(f"[{datetime.now()}] Results uploaded for {scan_id}")
        except Exception as e:
            print(f"[{datetime.now()}] Failed to upload results: {e}")
    
    def run(self):
        """Main agent loop"""
        print(f"[{datetime.now()}] SBOM Agent starting...")
        print(f"Agent ID: {self.agent_id}")
        print(f"Server: {self.server_url}")
        
        # Register on startup
        self.register()
        
        heartbeat_counter = 0
        
        while True:
            try:
                # Send heartbeat every 5 polls
                if heartbeat_counter % 5 == 0:
                    self.send_heartbeat()
                heartbeat_counter += 1
                
                # Check for pending work
                pending_scans = self.check_for_work()
                
                for scan in pending_scans:
                    scan_id = scan['scan_id']
                    scan_type = scan['scan_type']
                    
                    print(f"[{datetime.now()}] Processing scan: {scan_id}")
                    
                    # Mark as running
                    self.report_results(scan_id, "running", {})
                    
                    # Perform the scan
                    try:
                        results = self.perform_scan(scan_type)
                        self.report_results(scan_id, "completed", results)
                    except Exception as e:
                        print(f"[{datetime.now()}] Scan failed: {e}")
                        self.report_results(scan_id, "failed", {"error": str(e)})
                
                # Wait before next poll
                time.sleep(self.poll_interval)
            
            except KeyboardInterrupt:
                print("\n[{datetime.now()}] Shutting down...")
                break
            except Exception as e:
                print(f"[{datetime.now()}] Error in main loop: {e}")
                time.sleep(self.poll_interval)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent.py <config.yaml>")
        sys.exit(1)
    
    agent = SBOMAgent(sys.argv[1])
    agent.run()
```

**File: `agent/config.yaml`**

```yaml
agent:
  id: "agent-001"
  name: "Production Server 1"

server:
  url: "http://localhost:8000"
  
# How often to poll for work (seconds)
poll_interval: 30

# Enabled scanners
scanners:
  - apt
  - docker
```

---

### Phase 3: Web Interface (Week 3)

**File: `web/index.html`**

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
        <section class="stats">
            <div class="stat-card">
                <h3>Total Agents</h3>
                <p class="stat-value" id="total-agents">-</p>
            </div>
            <div class="stat-card">
                <h3>Active Agents</h3>
                <p class="stat-value" id="active-agents">-</p>
            </div>
            <div class="stat-card">
                <h3>Total Scans</h3>
                <p class="stat-value" id="total-scans">-</p>
            </div>
            <div class="stat-card critical">
                <h3>Vulnerabilities</h3>
                <p class="stat-value" id="total-vulns">-</p>
            </div>
        </section>

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
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td colspan="6">Loading...</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Trigger New Scan</h2>
            <form id="trigger-form">
                <label>
                    Agent:
                    <select id="agent-select" required>
                        <option value="">Loading agents...</option>
                    </select>
                </label>
                
                <label>
                    Scan Type:
                    <select id="scan-type" required>
                        <option value="apt">APT Packages</option>
                        <option value="rpm">RPM Packages</option>
                        <option value="docker">Docker Images (Trivy)</option>
                    </select>
                </label>
                
                <button type="submit">Trigger Scan</button>
            </form>
        </section>
    </main>

    <script src="/static/app.js"></script>
</body>
</html>
```

**File: `web/app.js`**

```javascript
// Simple vanilla JavaScript for the dashboard

// ============ API Client ============

const API_BASE = '/api';

async function fetchAPI(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

async function postAPI(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

// ============ Dashboard Updates ============

async function updateStats() {
    try {
        const stats = await fetchAPI('/stats');
        
        document.getElementById('total-agents').textContent = stats.total_agents;
        document.getElementById('active-agents').textContent = stats.active_agents;
        document.getElementById('total-scans').textContent = stats.total_scans;
        document.getElementById('total-vulns').textContent = stats.total_vulnerabilities;
    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

async function updateRecentScans() {
    try {
        const scans = await fetchAPI('/scans?limit=10');
        const tbody = document.querySelector('#recent-scans tbody');
        
        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6">No scans yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>${scan.scan_id}</td>
                <td>${scan.hostname || scan.agent_id}</td>
                <td>${scan.scan_type.toUpperCase()}</td>
                <td><span class="status-${scan.status}">${scan.status}</span></td>
                <td>${new Date(scan.started_at).toLocaleString()}</td>
                <td>
                    <a href="/static/scan-details.html?id=${scan.scan_id}">View</a>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to update scans:', error);
    }
}

async function loadAgents() {
    try {
        const agents = await fetchAPI('/agents');
        const select = document.getElementById('agent-select');
        
        if (agents.length === 0) {
            select.innerHTML = '<option value="">No agents available</option>';
            return;
        }
        
        select.innerHTML = agents
            .filter(a => a.status === 'active')
            .map(agent => `
                <option value="${agent.agent_id}">
                    ${agent.hostname || agent.agent_id} (${agent.status})
                </option>
            `).join('');
    } catch (error) {
        console.error('Failed to load agents:', error);
    }
}

// ============ Scan Triggering ============

document.getElementById('trigger-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const agentId = document.getElementById('agent-select').value;
    const scanType = document.getElementById('scan-type').value;
    
    if (!agentId) {
        alert('Please select an agent');
        return;
    }
    
    try {
        const result = await postAPI('/scans/trigger', {
            agent_id: agentId,
            scan_type: scanType
        });
        
        alert(`Scan triggered: ${result.scan_id}`);
        
        // Refresh the page after 2 seconds
        setTimeout(() => location.reload(), 2000);
    } catch (error) {
        alert(`Failed to trigger scan: ${error.message}`);
    }
});

// ============ Server-Sent Events ============

function connectSSE() {
    const eventSource = new EventSource('/api/events');
    
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('SSE Update:', data);
        
        // Refresh data when scans complete
        if (data.type === 'scan_complete') {
            updateRecentScans();
            updateStats();
        }
    };
    
    eventSource.onerror = () => {
        console.error('SSE connection error');
        eventSource.close();
        // Reconnect after 5 seconds
        setTimeout(connectSSE, 5000);
    };
}

// ============ Initialize ============

if (document.getElementById('total-agents')) {
    // Dashboard page
    updateStats();
    updateRecentScans();
    loadAgents();
    connectSSE();
    
    // Refresh every 30 seconds
    setInterval(() => {
        updateStats();
        updateRecentScans();
    }, 30000);
}
```

**File: `web/style.css`**

```css
/* Minimal, clean styling */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #333;
    background: #f5f5f5;
}

nav {
    background: #2c3e50;
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

nav h1 {
    font-size: 1.5rem;
}

.nav-links a {
    color: white;
    text-decoration: none;
    margin-left: 2rem;
    padding: 0.5rem 1rem;
    border-radius: 4px;
}

.nav-links a.active,
.nav-links a:hover {
    background: #34495e;
}

main {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
}

section {
    background: white;
    padding: 2rem;
    margin-bottom: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

h2 {
    margin-bottom: 1rem;
    color: #2c3e50;
}

/* Stats Cards */

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    padding: 1rem;
}

.stat-card {
    background: #ecf0f1;
    padding: 1.5rem;
    border-radius: 8px;
    text-align: center;
}

.stat-card.critical {
    background: #ffe5e5;
}

.stat-card h3 {
    font-size: 0.9rem;
    color: #7f8c8d;
    margin-bottom: 0.5rem;
}

.stat-value {
    font-size: 2.5rem;
    font-weight: bold;
    color: #2c3e50;
}

/* Table */

table {
    width: 100%;
    border-collapse: collapse;
}

th {
    background: #ecf0f1;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
}

td {
    padding: 1rem;
    border-bottom: 1px solid #ecf0f1;
}

tr:hover {
    background: #f8f9fa;
}

.status-pending { color: #f39c12; }
.status-running { color: #3498db; }
.status-completed { color: #27ae60; }
.status-failed { color: #e74c3c; }

/* Forms */

form {
    display: grid;
    gap: 1rem;
    max-width: 500px;
}

label {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-weight: 500;
}

select, input {
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
}

button {
    padding: 0.75rem 2rem;
    background: #3498db;
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
}

button:hover {
    background: #2980b9;
}

a {
    color: #3498db;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}
```

---

## Dependencies

**File: `requirements.txt`**

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-multipart==0.0.9
pyyaml==6.0.1
requests==2.31.0
python-jose[cryptography]==3.3.0
```

**Agent-specific:**
```txt
# agent/requirements.txt
pyyaml==6.0.1
requests==2.31.0
```

---

## Installation & Running

### Setup Script

**File: `setup.sh`**

```bash
#!/bin/bash

echo "Setting up SBOM Scanner..."

# Create directories
mkdir -p database web

# Create database
sqlite3 database/sbom.db < database/schema.sql

# Install Python dependencies
pip3 install -r requirements.txt

echo "Setup complete!"
echo ""
echo "To start the server:"
echo "  python3 server/main.py"
echo ""
echo "To start an agent:"
echo "  python3 agent/agent.py agent/config.yaml"
```

### Running Locally

```bash
# 1. Setup
chmod +x setup.sh
./setup.sh

# 2. Start server
python3 server/main.py
# Server runs on http://localhost:8000

# 3. Start agent (in another terminal)
python3 agent/agent.py agent/config.yaml

# 4. Access web interface
# Open http://localhost:8000 in browser
```

---

## Deployment (Single VPS)

### Systemd Services

**File: `/etc/systemd/system/sbom-server.service`**

```ini
[Unit]
Description=SBOM Scanner Server
After=network.target

[Service]
Type=simple
User=sbom
WorkingDirectory=/opt/sbom-scanner
ExecStart=/usr/bin/python3 server/main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**File: `/etc/systemd/system/sbom-agent.service`**

```ini
[Unit]
Description=SBOM Scanner Agent
After=network.target

[Service]
Type=simple
User=sbom
WorkingDirectory=/opt/sbom-scanner
ExecStart=/usr/bin/python3 agent/agent.py agent/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

**Enable and start:**

```bash
sudo systemctl enable sbom-server sbom-agent
sudo systemctl start sbom-server sbom-agent
sudo systemctl status sbom-server sbom-agent
```

---

## Why This Approach Works for Solo Developers

### ✅ No Complex Infrastructure
- **SQLite** instead of PostgreSQL - just a file
- **No Redis** - no separate service to manage
- **No Celery** - no distributed task queue
- **HTTP polling** - no persistent WebSocket connections

### ✅ Single-File Deployment
- Everything runs as simple Python processes
- No containers required (but optional)
- Can run on a $5/month VPS

### ✅ Minimal Dependencies
- 6 Python packages total
- No Node.js build process
- No complex frontend tooling

### ✅ Easy to Understand
- ~300 lines for server
- ~200 lines for agent
- ~150 lines of JavaScript
- Clear, linear code flow

### ✅ Gradual Growth Path
When you outgrow this:
1. Swap SQLite → PostgreSQL (one line change)
2. Add Celery only when needed
3. Upgrade to React if UI gets complex
4. Add Docker only for deployment

---

## What You Can Actually Build

**Week 1:** Working API server with database
**Week 2:** Functioning agent that scans packages
**Week 3:** Web interface to view results
**Week 4:** Polish, bug fixes, documentation

**Total:** One month to a working system you can deploy and maintain solo.

This follows the PDF's principle: **"Taking too much time on the architectural phase is prohibitive in business contexts."** Start simple, ship fast, iterate based on real needs.
