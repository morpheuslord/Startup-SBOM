"""
SBOM Scanner — FastAPI Server
All endpoints in a single file for simplicity.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import json
import mimetypes
import uvicorn
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from sbom_server.database import get_db, init_database, dict_from_row
from sbom_core.config import settings

# ─── Paths ──────────────────────────────────────────────────────────────
WEB_DIR = Path(__file__).resolve().parent.parent.parent / "web"

# Global list for SSE connections
active_sse_connections: List[asyncio.Queue] = []


# ─── Lifespan ───────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    # Startup
    db_path = Path(settings.server.db_path)
    if not db_path.exists():
        # Ensure directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)
        init_database()
        print(f"Database initialized at {db_path}")
    else:
        print(f"Database already exists at {db_path}")
        
    print(f"Server starting on http://{settings.server.host}:{settings.server.port}")
    yield
    # Shutdown
    print("Server shutting down...")


# ─── App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SBOM Scanner",
    description="Distributed SBOM scanning system",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Static File Serving (explicit routes) ──────────────────────────────
@app.get("/static/{filename:path}")
async def serve_static(filename: str):
    """Serve static files from web/ directory with proper Content-Type"""
    file_path = WEB_DIR / filename

    # Security: prevent path traversal
    try:
        file_path = file_path.resolve()
        if not str(file_path).startswith(str(WEB_DIR.resolve())):
            raise HTTPException(status_code=403, detail="Forbidden")
    except Exception:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    # Determine content type
    content_type, _ = mimetypes.guess_type(str(file_path))
    if content_type is None:
        content_type = "application/octet-stream"

    # Read file
    if content_type.startswith("text/") or content_type in (
        "application/javascript",
        "application/json",
    ):
        content = file_path.read_text(encoding="utf-8")
    else:
        content = file_path.read_bytes()

    return Response(
        content=content,
        media_type=content_type,
        headers={"Cache-Control": "no-cache"},
    )


# ─── Root & Health ──────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    html_path = WEB_DIR / "index.html"
    try:
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>SBOM Scanner</h1><p>Web interface not found. Check web/ directory.</p>"
        )


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }


# ─── Agent Management ──────────────────────────────────────────────────
@app.post("/api/agents/register")
async def register_agent(agent_data: Dict[str, Any]):
    """Register or update an agent"""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (agent_data["agent_id"],),
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                """
                UPDATE agents
                SET hostname = ?, ip_address = ?, os_info = ?,
                    status = 'active', last_heartbeat = ?
                WHERE agent_id = ?
                """,
                (
                    agent_data.get("hostname"),
                    agent_data.get("ip_address"),
                    agent_data.get("os_info"),
                    datetime.utcnow().isoformat(),
                    agent_data["agent_id"],
                ),
            )
            message = "updated"
        else:
            cursor.execute(
                """
                INSERT INTO agents (agent_id, hostname, ip_address, os_info, status, last_heartbeat)
                VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (
                    agent_data["agent_id"],
                    agent_data.get("hostname"),
                    agent_data.get("ip_address"),
                    agent_data.get("os_info"),
                    datetime.utcnow().isoformat(),
                ),
            )
            message = "registered"

        conn.commit()

        return {
            "status": message,
            "agent_id": agent_data["agent_id"],
            "timestamp": datetime.utcnow().isoformat(),
        }


@app.get("/api/agents")
async def list_agents():
    """List all registered agents"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT agent_id, hostname, ip_address, os_info, status,
                   last_heartbeat, registered_at
            FROM agents
            ORDER BY registered_at DESC
            """
        )

        agents = []
        for row in cursor.fetchall():
            agent = dict_from_row(row)

            if agent["last_heartbeat"]:
                try:
                    last_hb = datetime.fromisoformat(str(agent["last_heartbeat"]))
                    if datetime.utcnow() - last_hb > timedelta(minutes=5):
                        agent["status"] = "inactive"
                except (ValueError, TypeError):
                    pass

            agents.append(agent)

        return agents


@app.get("/api/agents/{agent_id}")
async def get_agent(agent_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))

        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")

        return dict_from_row(row)


@app.post("/api/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE agents SET last_heartbeat = ?, status = 'active' WHERE agent_id = ?",
            (datetime.utcnow().isoformat(), agent_id),
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Agent not found")

        conn.commit()

        return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.delete("/api/agents/{agent_id}")
async def delete_agent(agent_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Agent not found")

        conn.commit()
        return {"status": "deleted", "agent_id": agent_id}


# ─── Scan Management ───────────────────────────────────────────────────
@app.post("/api/scans")
async def create_scan(scan_data: Dict[str, Any]):
    """Create a new scan record (called by agents)"""
    with get_db() as conn:
        cursor = conn.cursor()

        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{scan_data['agent_id']}"

        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (scan_data["agent_id"],),
        )
        agent_row = cursor.fetchone()
        if not agent_row:
            raise HTTPException(status_code=404, detail="Agent not found")

        agent_db_id = agent_row[0]

        cursor.execute(
            """
            INSERT INTO scans (scan_id, agent_id, scan_type, target_path, status, started_at)
            VALUES (?, ?, ?, ?, 'running', ?)
            """,
            (
                scan_id,
                agent_db_id,
                scan_data.get("scan_type", "unknown"),
                scan_data.get("target_path", "/"),
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        return {
            "scan_id": scan_id,
            "status": "created",
            "timestamp": datetime.utcnow().isoformat(),
        }


@app.put("/api/scans/{scan_id}/results")
async def update_scan_results(
    scan_id: str,
    results: Dict[str, Any],
    background_tasks: BackgroundTasks,
):
    """Update scan with results (called by agents)"""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM scans WHERE scan_id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_db_id = scan_row[0]

        status = results.get("status", "completed")
        cursor.execute(
            """
            UPDATE scans
            SET status = ?,
                completed_at = ?,
                error_message = ?,
                result_json = ?
            WHERE scan_id = ?
            """,
            (
                status,
                datetime.utcnow().isoformat() if status in ["completed", "failed"] else None,
                results.get("error_message"),
                json.dumps(results.get("data", {})),
                scan_id,
            ),
        )

        # Store packages
        if "packages" in results.get("data", {}):
            for pkg in results["data"]["packages"]:
                cursor.execute(
                    """
                    INSERT INTO packages (scan_id, name, version, package_manager, architecture, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_db_id,
                        pkg.get("name"),
                        pkg.get("version"),
                        pkg.get("package_manager"),
                        pkg.get("architecture"),
                        json.dumps(pkg.get("metadata", {})),
                    ),
                )

        # Store vulnerabilities
        if "vulnerabilities" in results.get("data", {}):
            for vuln in results["data"]["vulnerabilities"]:
                cursor.execute(
                    """
                    INSERT INTO vulnerabilities
                    (scan_id, cve_id, severity, package_name, package_version, description, cvss_score, fixed_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_db_id,
                        vuln.get("cve_id"),
                        vuln.get("severity"),
                        vuln.get("package_name"),
                        vuln.get("package_version"),
                        (vuln.get("description", "") or "")[:500],
                        vuln.get("cvss_score"),
                        vuln.get("fixed_version"),
                    ),
                )

        conn.commit()

        # Notify SSE clients
        background_tasks.add_task(
            notify_sse_clients,
            {"type": "scan_update", "scan_id": scan_id, "status": status},
        )

        return {"status": "updated", "scan_id": scan_id}


@app.get("/api/scans")
async def list_scans(
    limit: int = 50,
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
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
        return [dict_from_row(row) for row in cursor.fetchall()]


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get detailed scan results including packages and vulnerabilities"""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT s.*, a.agent_id as agent_identifier, a.hostname
            FROM scans s
            JOIN agents a ON s.agent_id = a.id
            WHERE s.scan_id = ?
            """,
            (scan_id,),
        )

        scan_row = cursor.fetchone()
        if not scan_row:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = dict_from_row(scan_row)
        scan_db_id = scan["id"]

        # Parse result_json
        if scan.get("result_json"):
            try:
                scan["results"] = json.loads(scan["result_json"])
            except (json.JSONDecodeError, TypeError):
                scan["results"] = {}

        # Packages
        cursor.execute(
            """
            SELECT name, version, package_manager, architecture
            FROM packages WHERE scan_id = ? ORDER BY name
            """,
            (scan_db_id,),
        )
        scan["packages"] = [dict_from_row(r) for r in cursor.fetchall()]

        # Vulnerabilities (ordered by severity)
        cursor.execute(
            """
            SELECT cve_id, severity, package_name, package_version,
                   description, cvss_score, fixed_version
            FROM vulnerabilities WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
            """,
            (scan_db_id,),
        )
        scan["vulnerabilities"] = [dict_from_row(r) for r in cursor.fetchall()]

        # Stats summary
        scan["stats"] = {
            "package_count": len(scan["packages"]),
            "vulnerability_count": len(scan["vulnerabilities"]),
            "critical_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "CRITICAL"),
            "high_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "HIGH"),
            "medium_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "MEDIUM"),
            "low_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "LOW"),
        }

        return scan


@app.post("/api/scans/trigger")
async def trigger_scan(trigger_data: Dict[str, Any]):
    """Queue a scan for an agent to pick up"""
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM agents WHERE agent_id = ?",
            (trigger_data["agent_id"],),
        )
        agent_row = cursor.fetchone()
        if not agent_row:
            raise HTTPException(status_code=404, detail="Agent not found")

        agent_db_id = agent_row[0]
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{trigger_data['agent_id']}"

        cursor.execute(
            """
            INSERT INTO scans (scan_id, agent_id, scan_type, target_path, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (
                scan_id,
                agent_db_id,
                trigger_data.get("scan_type", "apt"),
                trigger_data.get("target_path", "/"),
            ),
        )

        conn.commit()
        return {
            "scan_id": scan_id,
            "status": "pending",
            "message": "Scan queued for agent to pick up",
        }


@app.get("/api/agents/{agent_id}/pending-scans")
async def get_pending_scans(agent_id: str):
    """Get pending scans for a specific agent"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.scan_id, s.scan_type, s.target_path
            FROM scans s
            JOIN agents a ON s.agent_id = a.id
            WHERE a.agent_id = ? AND s.status = 'pending'
            ORDER BY s.id ASC
            """,
            (agent_id,),
        )
        return [dict_from_row(row) for row in cursor.fetchall()]


# ─── Statistics ─────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_statistics():
    """Get dashboard statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        stats = {}

        cursor.execute("SELECT COUNT(*) FROM agents")
        stats["total_agents"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM agents WHERE last_heartbeat > datetime('now', '-5 minutes')"
        )
        stats["active_agents"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scans")
        stats["total_scans"] = cursor.fetchone()[0]

        cursor.execute("SELECT status, COUNT(*) FROM scans GROUP BY status")
        stats["scans_by_status"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats["total_vulnerabilities"] = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")
        stats["vulnerabilities_by_severity"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            "SELECT COUNT(*) FROM scans WHERE started_at > datetime('now', '-24 hours')"
        )
        stats["scans_last_24h"] = cursor.fetchone()[0]

        return stats


# ─── Server-Sent Events (SSE) ──────────────────────────────────────────
async def notify_sse_clients(message: Dict[str, Any]):
    """Send message to all connected SSE clients"""
    for queue in active_sse_connections:
        try:
            await queue.put(message)
        except Exception:
            pass


@app.get("/api/events")
async def sse_endpoint():
    """SSE endpoint for real-time updates"""

    async def event_generator():
        queue = asyncio.Queue()
        active_sse_connections.append(queue)

        try:
            while True:
                message = await queue.get()
                yield "data: " + json.dumps(message) + "\n\n"
        except asyncio.CancelledError:
            if queue in active_sse_connections:
                active_sse_connections.remove(queue)
            raise

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


# ─── Entry Point ────────────────────────────────────────────────────────
def start():
    uvicorn.run(
        "sbom_server.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=True,
        log_level="info",
    )

if __name__ == "__main__":
    start()
