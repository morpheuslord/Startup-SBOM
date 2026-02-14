#!/usr/bin/env python3
"""
SBOM Scanner Agent
Polls server for work and executes scans
"""
import time
import requests
import socket
import platform
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from sbom_core.config import settings


class SBOMAgent:
    def __init__(self):
        self.config = settings.agent
        self.agent_id = self.config.id
        self.server_url = self.config.server_url.rstrip("/")
        self.poll_interval = self.config.poll_interval
        
        # Auto-detect scanners
        self.enabled_scanners = self._detect_scanners()

        print(f"[{self._ts()}] SBOM Agent initialized")
        print(f"  Agent ID : {self.agent_id}")
        print(f"  Server   : {self.server_url}")
        print(f"  Scanners : {', '.join(self.enabled_scanners)}")

    def _detect_scanners(self) -> List[str]:
        scanners = []
        # Check for APT
        if self._command_exists("dpkg-query"):
            scanners.append("apt")
        # Check for RPM
        if self._command_exists("rpm"):
            scanners.append("rpm")
        # Check for Docker
        if self._command_exists("docker"):
            scanners.append("docker")
        
        if not scanners:
            print(f"[{self._ts()}] WARNING: No supported package managers or tools found!")
            
        return scanners

    def _command_exists(self, cmd: str) -> bool:
        try:
            subprocess.run(["which", cmd], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            # 'which' command might not exist on some minimal containers, 
            # try running the command itself with --version or similar if applicable
            # But standard linux usually has 'which' or 'command -v'.
            # Fallback: try calling the command directly
            try:
                subprocess.run([cmd, "--version"], capture_output=True, check=True)
                return True
            except Exception:
                return False

    # ── helpers ──────────────────────────────────────────────────────
    def _ts(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        url = f"{self.server_url}{endpoint}"
        try:
            r = requests.request(method, url, timeout=10, **kwargs)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            print(f"[{self._ts()}] Request failed: {e}")
            return None

    # ── lifecycle ────────────────────────────────────────────────────
    def get_system_info(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "hostname": self.config.hostname or socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_info": platform.platform(),
        }

    def register(self) -> bool:
        result = self._request("POST", "/api/agents/register", json=self.get_system_info())
        if result:
            print(f"[{self._ts()}] Registered with server")
            return True
        print(f"[{self._ts()}] Failed to register")
        return False

    def send_heartbeat(self):
        self._request("POST", f"/api/agents/{self.agent_id}/heartbeat")

    def check_for_work(self) -> List[Dict]:
        result = self._request("GET", f"/api/agents/{self.agent_id}/pending-scans")
        return result if result else []

    def report_results(self, scan_id: str, status: str, data: Dict):
        result = self._request(
            "PUT",
            f"/api/scans/{scan_id}/results",
            json={"status": status, "data": data},
        )
        if result:
            print(f"[{self._ts()}] Results uploaded for {scan_id}")
        else:
            print(f"[{self._ts()}] Failed to upload results")

    # ── scanners ─────────────────────────────────────────────────────
    def scan_apt_packages(self) -> Dict:
        """Scan APT packages (Debian/Ubuntu)"""
        print(f"[{self._ts()}] Scanning APT packages...")
        packages: List[Dict] = []

        try:
            check = subprocess.run(["which", "dpkg-query"], capture_output=True, text=True)
            if check.returncode != 0:
                return {"error": "dpkg-query not found", "packages": []}

            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}\\n"],
                capture_output=True,
                text=True,
                check=True,
            )

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) >= 2:
                    packages.append(
                        {
                            "name": parts[0],
                            "version": parts[1],
                            "architecture": parts[2] if len(parts) > 2 else "unknown",
                            "package_manager": "apt",
                        }
                    )

            print(f"[{self._ts()}] Found {len(packages)} APT packages")

        except subprocess.CalledProcessError as e:
            return {"error": f"dpkg-query failed: {e}", "packages": []}
        except Exception as e:
            return {"error": str(e), "packages": []}

        return {"packages": packages, "total_count": len(packages)}

    def scan_rpm_packages(self) -> Dict:
        """Scan RPM packages (RHEL/CentOS/Fedora)"""
        print(f"[{self._ts()}] Scanning RPM packages...")
        packages: List[Dict] = []

        try:
            check = subprocess.run(["which", "rpm"], capture_output=True, text=True)
            if check.returncode != 0:
                return {"error": "rpm not found", "packages": []}

            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\\n"],
                capture_output=True,
                text=True,
                check=True,
            )

            for line in result.stdout.strip().split("\\n"):
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) >= 2:
                    packages.append(
                        {
                            "name": parts[0],
                            "version": parts[1],
                            "architecture": parts[2] if len(parts) > 2 else "unknown",
                            "package_manager": "rpm",
                        }
                    )

            print(f"[{self._ts()}] Found {len(packages)} RPM packages")

        except subprocess.CalledProcessError as e:
            return {"error": f"rpm failed: {e}", "packages": []}
        except Exception as e:
            return {"error": str(e), "packages": []}

        return {"packages": packages, "total_count": len(packages)}

    def scan_docker_images(self) -> Dict:
        """Scan Docker images with Trivy"""
        print(f"[{self._ts()}] Scanning Docker images...")
        images: List[Dict] = []
        vulnerabilities: List[Dict] = []

        try:
            docker_check = subprocess.run(["which", "docker"], capture_output=True, text=True)
            if docker_check.returncode != 0:
                return {"error": "Docker not found", "images": [], "vulnerabilities": []}

            trivy_check = subprocess.run(["which", "trivy"], capture_output=True, text=True)
            if trivy_check.returncode != 0:
                return {
                    "error": "Trivy not found. Install from https://aquasecurity.github.io/trivy/",
                    "images": [],
                    "vulnerabilities": [],
                }

            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                check=True,
            )

            image_names = [
                line.strip()
                for line in result.stdout.strip().split("\\n")
                if line and "<none>" not in line
            ]

            for image_name in image_names:
                print(f"[{self._ts()}] Scanning {image_name}...")

                try:
                    trivy_result = subprocess.run(
                        ["trivy", "image", "--format", "json", "--quiet", image_name],
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )

                    if trivy_result.returncode == 0:
                        trivy_data = json.loads(trivy_result.stdout)
                        image_vulns: List[Dict] = []

                        for result_item in trivy_data.get("Results", []):
                            for vuln in result_item.get("Vulnerabilities", []):
                                image_vulns.append(
                                    {
                                        "cve_id": vuln.get("VulnerabilityID"),
                                        "severity": vuln.get("Severity"),
                                        "package_name": vuln.get("PkgName"),
                                        "package_version": vuln.get("InstalledVersion"),
                                        "description": (
                                            vuln.get("Description", "") or vuln.get("Title", "")
                                        )[:200],
                                        "fixed_version": vuln.get("FixedVersion"),
                                        "cvss_score": self._extract_cvss(vuln),
                                    }
                                )

                        images.append(
                            {"image": image_name, "vulnerability_count": len(image_vulns)}
                        )
                        vulnerabilities.extend(image_vulns)
                        print(
                            f"[{self._ts()}] Found {len(image_vulns)} vulns in {image_name}"
                        )

                except subprocess.TimeoutExpired:
                    print(f"[{self._ts()}] Timeout scanning {image_name}")
                except Exception as e:
                    print(f"[{self._ts()}] Error scanning {image_name}: {e}")

        except subprocess.CalledProcessError as e:
            return {"error": f"Docker failed: {e}", "images": [], "vulnerabilities": []}
        except Exception as e:
            return {"error": str(e), "images": [], "vulnerabilities": []}

        return {
            "images": images,
            "vulnerabilities": vulnerabilities,
            "total_images": len(images),
            "total_vulnerabilities": len(vulnerabilities),
        }

    def _extract_cvss(self, vuln: Dict) -> str:
        try:
            cvss = vuln.get("CVSS", {})
            for _vendor, data in cvss.items():
                if isinstance(data, dict) and "V3Score" in data:
                    return str(data["V3Score"])
            return "N/A"
        except Exception:
            return "N/A"

    def perform_scan(self, scan_type: str) -> Dict:
        if scan_type == "apt":
            return self.scan_apt_packages()
        elif scan_type == "rpm":
            return self.scan_rpm_packages()
        elif scan_type == "docker":
            return self.scan_docker_images()
        else:
            return {"error": f"Unknown scan type: {scan_type}"}

    # ── main loop ────────────────────────────────────────────────────
    def run(self):
        print(f"[{self._ts()}] Starting SBOM Agent...")

        if not self.register():
            print(f"[{self._ts()}] Failed to register. Exiting.")
            return

        heartbeat_counter = 0

        try:
            while True:
                if heartbeat_counter % 5 == 0:
                    self.send_heartbeat()
                heartbeat_counter += 1

                pending_scans = self.check_for_work()

                for scan in pending_scans:
                    scan_id = scan["scan_id"]
                    scan_type = scan["scan_type"]
                    print(
                        f"[{self._ts()}] Processing scan: {scan_id} (type: {scan_type})"
                    )

                    self.report_results(scan_id, "running", {})

                    try:
                        results = self.perform_scan(scan_type)
                        if "error" in results:
                            self.report_results(scan_id, "failed", results)
                        else:
                            self.report_results(scan_id, "completed", results)
                    except Exception as e:
                        print(f"[{self._ts()}] Scan failed: {e}")
                        self.report_results(scan_id, "failed", {"error": str(e)})

                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            print(f"\\n[{self._ts()}] Shutting down...")
        except Exception as e:
            print(f"[{self._ts()}] Fatal error: {e}")
            raise


def start():
    try:
        agent = SBOMAgent()
        agent.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start()
