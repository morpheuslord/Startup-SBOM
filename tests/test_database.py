"""
Tests for the database module.
"""
import sqlite3
from pathlib import Path

import pytest


class TestDatabaseInit:
    def test_schema_creates_tables(self, test_db):
        """Schema should create all expected tables"""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        expected = {"agents", "scans", "packages", "vulnerabilities", "docker_images", "misconfigurations"}
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_agents_table_columns(self, test_db):
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(agents)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {"id", "agent_id", "hostname", "ip_address", "os_info", "status", "last_heartbeat", "config_json"}
        assert required.issubset(columns)

    def test_docker_images_table_columns(self, test_db):
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(docker_images)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {"id", "scan_id", "image_name", "tag", "vulnerability_count", "critical_count", "high_count", "medium_count", "low_count"}
        assert required.issubset(columns)

    def test_misconfigurations_table_columns(self, test_db):
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(misconfigurations)")
        columns = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {"id", "scan_id", "check_id", "check_title", "severity", "status", "resource", "description", "remediation", "source"}
        assert required.issubset(columns)

    def test_insert_docker_image(self, test_db):
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        # Insert an agent and scan first
        cursor.execute("INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'h1')")
        agent_id = cursor.lastrowid
        cursor.execute("INSERT INTO scans (scan_id, agent_id, scan_type) VALUES ('s1', ?, 'docker')", (agent_id,))
        scan_id = cursor.lastrowid

        cursor.execute(
            """INSERT INTO docker_images (scan_id, image_name, tag, vulnerability_count, critical_count, high_count, medium_count, low_count)
               VALUES (?, 'nginx', 'latest', 10, 2, 3, 4, 1)""",
            (scan_id,),
        )
        conn.commit()

        cursor.execute("SELECT * FROM docker_images WHERE image_name = 'nginx'")
        row = cursor.fetchone()
        conn.close()

        assert row is not None

    def test_insert_misconfiguration(self, test_db):
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO agents (agent_id, hostname) VALUES ('a2', 'h2')")
        agent_id = cursor.lastrowid
        cursor.execute("INSERT INTO scans (scan_id, agent_id, scan_type) VALUES ('s2', ?, 'prowler')", (agent_id,))
        scan_id = cursor.lastrowid

        cursor.execute(
            """INSERT INTO misconfigurations (scan_id, check_id, check_title, severity, status, resource, source)
               VALUES (?, 'P001', 'Root Login', 'HIGH', 'FAIL', '/etc/ssh', 'prowler')""",
            (scan_id,),
        )
        conn.commit()

        cursor.execute("SELECT * FROM misconfigurations WHERE check_id = 'P001'")
        row = cursor.fetchone()
        conn.close()

        assert row is not None

    def test_foreign_key_relationship(self, test_db):
        """Scans should reference agents properly"""
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO agents (agent_id) VALUES ('fk-agent')")
        agent_id = cursor.lastrowid

        cursor.execute("INSERT INTO scans (scan_id, agent_id) VALUES ('fk-scan', ?)", (agent_id,))
        scan_id = cursor.lastrowid

        cursor.execute("INSERT INTO packages (scan_id, name, version) VALUES (?, 'pkg', '1.0')", (scan_id,))
        cursor.execute("INSERT INTO vulnerabilities (scan_id, cve_id, severity) VALUES (?, 'CVE-2024-0001', 'HIGH')", (scan_id,))
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM packages WHERE scan_id = ?", (scan_id,))
        assert cursor.fetchone()[0] == 1

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        assert cursor.fetchone()[0] == 1

        conn.close()
