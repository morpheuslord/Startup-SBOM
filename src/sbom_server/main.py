"""
SBOM Scanner — FastAPI Server
All endpoints in a single file for simplicity.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging
import json
import mimetypes
import uvicorn
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

# ─── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sbom-server")

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
        logger.info(f"Database initialized at {db_path}")
    else:
        # Re-init to add any new tables (CREATE TABLE IF NOT EXISTS is safe)
        init_database()
        logger.info(f"Database updated at {db_path}")

    logger.info(f"Server starting on http://{settings.server.host}:{settings.server.port}")
    yield
    # Shutdown
    logger.info("Server shutting down...")


# ─── App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SBOM Scanner",
    description="Distributed SBOM scanning system",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Static Files & UI ──────────────────────────────────────────────────
# Mount static files (style.css, app.js)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

@app.get("/", response_class=FileResponse)
async def serve_index():
    """Serve the main dashboard UI"""
    index_path = WEB_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


# ─── API Endpoints ──────────────────────────────────────────────────────


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
        "version": "2.0.0",
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
                    status = 'active', last_heartbeat = ?,
                    config_json = ?
                WHERE agent_id = ?
                """,
                (
                    agent_data.get("hostname"),
                    agent_data.get("ip_address"),
                    agent_data.get("os_info"),
                    datetime.utcnow().isoformat(),
                    json.dumps({"scanners": agent_data.get("scanners", [])}),
                    agent_data["agent_id"],
                ),
            )
            message = "updated"
        else:
            cursor.execute(
                """
                INSERT INTO agents (agent_id, hostname, ip_address, os_info, status, last_heartbeat, config_json)
                VALUES (?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    agent_data["agent_id"],
                    agent_data.get("hostname"),
                    agent_data.get("ip_address"),
                    agent_data.get("os_info"),
                    datetime.utcnow().isoformat(),
                    json.dumps({"scanners": agent_data.get("scanners", [])}),
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
                   last_heartbeat, registered_at, config_json
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

            # Parse config_json for scanners info
            if agent.get("config_json"):
                try:
                    agent["config"] = json.loads(agent["config_json"])
                except (json.JSONDecodeError, TypeError):
                    agent["config"] = {}

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

        agent = dict_from_row(row)
        if agent.get("config_json"):
            try:
                agent["config"] = json.loads(agent["config_json"])
            except (json.JSONDecodeError, TypeError):
                agent["config"] = {}

        return agent


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

        data = results.get("data", {})

        # Store packages
        if "packages" in data:
            for pkg in data["packages"]:
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
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
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

        # Store Docker images
        if "images" in data:
            for img in data["images"]:
                cursor.execute(
                    """
                    INSERT INTO docker_images
                    (scan_id, image_name, tag, vulnerability_count,
                     critical_count, high_count, medium_count, low_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_db_id,
                        img.get("image_name"),
                        img.get("tag"),
                        img.get("vulnerability_count", 0),
                        img.get("critical_count", 0),
                        img.get("high_count", 0),
                        img.get("medium_count", 0),
                        img.get("low_count", 0),
                    ),
                )

        # Store misconfigurations
        if "misconfigurations" in data:
            for mc in data["misconfigurations"]:
                cursor.execute(
                    """
                    INSERT INTO misconfigurations
                    (scan_id, check_id, check_title, severity, status, resource, description, remediation, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_db_id,
                        mc.get("check_id"),
                        mc.get("check_title"),
                        mc.get("severity"),
                        mc.get("status"),
                        mc.get("resource"),
                        (mc.get("description", "") or "")[:500],
                        (mc.get("remediation", "") or "")[:500],
                        mc.get("source", "unknown"),
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
    scan_type: Optional[str] = None,
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

        if scan_type:
            query += " AND s.scan_type = ?"
            params.append(scan_type)

        query += " ORDER BY s.started_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict_from_row(row) for row in cursor.fetchall()]


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Get detailed scan results including packages, vulnerabilities, docker images, and misconfigs"""
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

        # Docker images
        cursor.execute(
            """
            SELECT image_name, tag, vulnerability_count,
                   critical_count, high_count, medium_count, low_count, scanned_at
            FROM docker_images WHERE scan_id = ?
            ORDER BY vulnerability_count DESC
            """,
            (scan_db_id,),
        )
        scan["docker_images"] = [dict_from_row(r) for r in cursor.fetchall()]

        # Misconfigurations
        cursor.execute(
            """
            SELECT check_id, check_title, severity, status, resource,
                   description, remediation, source
            FROM misconfigurations WHERE scan_id = ?
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
        scan["misconfigurations"] = [dict_from_row(r) for r in cursor.fetchall()]

        # Stats summary
        scan["stats"] = {
            "package_count": len(scan["packages"]),
            "vulnerability_count": len(scan["vulnerabilities"]),
            "critical_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "CRITICAL"),
            "high_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "HIGH"),
            "medium_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "MEDIUM"),
            "low_count": sum(1 for v in scan["vulnerabilities"] if v["severity"] == "LOW"),
            "docker_image_count": len(scan["docker_images"]),
            "misconfiguration_count": len(scan["misconfigurations"]),
            "misconfig_fail_count": sum(1 for m in scan["misconfigurations"] if m["status"] == "FAIL"),
            "misconfig_pass_count": sum(1 for m in scan["misconfigurations"] if m["status"] == "PASS"),
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


# ─── Docker Images Endpoints ───────────────────────────────────────────
@app.get("/api/docker-images")
async def list_docker_images(limit: int = 100):
    """List all scanned Docker images"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT di.*, s.scan_id as scan_identifier, a.agent_id as agent_identifier, a.hostname
            FROM docker_images di
            JOIN scans s ON di.scan_id = s.id
            JOIN agents a ON s.agent_id = a.id
            ORDER BY di.scanned_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict_from_row(row) for row in cursor.fetchall()]


@app.get("/api/docker-images/{scan_id}")
async def get_docker_images_by_scan(scan_id: str):
    """Get Docker images for a specific scan"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT di.*
            FROM docker_images di
            JOIN scans s ON di.scan_id = s.id
            WHERE s.scan_id = ?
            ORDER BY di.vulnerability_count DESC
            """,
            (scan_id,),
        )
        return [dict_from_row(row) for row in cursor.fetchall()]


# ─── Misconfigurations Endpoints ───────────────────────────────────────
@app.get("/api/misconfigurations")
async def list_misconfigurations(
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
):
    """List misconfigurations with optional filters"""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT m.*, s.scan_id as scan_identifier, a.agent_id as agent_identifier, a.hostname
            FROM misconfigurations m
            JOIN scans s ON m.scan_id = s.id
            JOIN agents a ON s.agent_id = a.id
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND m.severity = ?"
            params.append(severity.upper())

        if status:
            query += " AND m.status = ?"
            params.append(status.upper())

        if source:
            query += " AND m.source = ?"
            params.append(source)

        query += """
            ORDER BY
                CASE m.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
        return [dict_from_row(row) for row in cursor.fetchall()]


# ─── Vulnerabilities Endpoint ──────────────────────────────────────────
@app.get("/api/vulnerabilities")
async def list_vulnerabilities(
    limit: int = 100,
    severity: Optional[str] = None,
    search: Optional[str] = None,
):
    """List all vulnerabilities with optional filters"""
    with get_db() as conn:
        cursor = conn.cursor()

        query = """
            SELECT v.*, s.scan_id as scan_identifier, s.scan_type,
                   a.agent_id as agent_identifier, a.hostname
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            JOIN agents a ON s.agent_id = a.id
            WHERE 1=1
        """
        params = []

        if severity:
            query += " AND v.severity = ?"
            params.append(severity.upper())

        if search:
            query += " AND (v.cve_id LIKE ? OR v.package_name LIKE ? OR v.description LIKE ?)"
            search_pattern = f"%{search}%"
            params.extend([search_pattern, search_pattern, search_pattern])

        query += """
            ORDER BY
                CASE v.severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
            LIMIT ?
        """
        params.append(limit)

        cursor.execute(query, params)
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

        # Docker image stats
        cursor.execute("SELECT COUNT(*) FROM docker_images")
        stats["total_docker_images"] = cursor.fetchone()[0]

        cursor.execute("SELECT SUM(vulnerability_count) FROM docker_images")
        row = cursor.fetchone()
        stats["total_docker_vulns"] = row[0] if row[0] else 0

        # Misconfiguration stats
        cursor.execute("SELECT COUNT(*) FROM misconfigurations")
        stats["total_misconfigurations"] = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM misconfigurations GROUP BY severity")
        stats["misconfigs_by_severity"] = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT status, COUNT(*) FROM misconfigurations GROUP BY status")
        stats["misconfigs_by_status"] = {row[0]: row[1] for row in cursor.fetchall()}

        # Scan type breakdown
        cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
        stats["scans_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}

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
    # Detect if we are in Docker or have an explicit config path
    # Usually we don't want reload in production or Docker to avoid strange reset issues
    is_docker = Path("/.dockerenv").exists()
    do_reload = not is_docker and settings.server.host in ("127.0.0.1", "localhost")

    logger.info(f"Starting uvicorn (reload={do_reload})")

    uvicorn.run(
        "sbom_server.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=do_reload,
        log_level="info",
    )

if __name__ == "__main__":
    start()
