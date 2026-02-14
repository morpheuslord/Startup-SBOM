-- SBOM Scanner Database Schema (SQLite)
-- Tables for agents, scans, packages, and vulnerabilities

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
