#!/usr/bin/env python3
"""
SBOM Scanner Agent
Polls server for work and executes scans using Trivy, Prowler, and native package managers.
"""
import time
import requests
import socket
import platform
import logging
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# ─── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sbom-agent")

from sbom_core.config import settings


class SBOMAgent:
    def __init__(self):
        self.config = settings.agent
        self.agent_id = self.config.id
        self.server_url = self.config.server_url.rstrip("/")
        self.poll_interval = self.config.poll_interval
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Auto-detect scanners
        self.enabled_scanners = self._detect_scanners()

        logger.info("SBOM Agent initialized")
        logger.info(f"  Agent ID : {self.agent_id}")
        logger.info(f"  Server   : {self.server_url}")
        logger.info(f"  Output   : {self.output_dir}")
        logger.info(f"  Scanners : {', '.join(self.enabled_scanners)}")

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
        # Check for Trivy (filesystem scanning)
        if self._command_exists("trivy"):
            scanners.append("trivy-fs")
        # Check for Prowler
        if self._command_exists("prowler"):
            scanners.append("prowler")

        if not scanners:
            logger.warning("No supported package managers or tools found!")

        return scanners

    def _command_exists(self, cmd: str) -> bool:
        try:
            subprocess.run(["which", cmd], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            try:
                subprocess.run([cmd, "--version"], capture_output=True, check=True)
                return True
            except Exception:
                return False

    # ── helpers ──────────────────────────────────────────────────────

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        url = f"{self.server_url}{endpoint}"
        try:
            r = requests.request(method, url, timeout=30, **kwargs)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None

    def _save_output(self, scan_type: str, data: Dict):
        """Save scan output to the shared output directory as JSON."""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.output_dir / filename
            filepath.write_text(json.dumps(data, indent=2))
            logger.info(f"Output saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save output: {e}")

    # ── lifecycle ────────────────────────────────────────────────────
    def get_system_info(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "hostname": self.config.hostname or socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_info": platform.platform(),
            "scanners": self.enabled_scanners,
        }

    def register(self) -> bool:
        result = self._request("POST", "/api/agents/register", json=self.get_system_info())
        if result:
            logger.info("Registered with server")
            return True
        logger.error("Failed to register")
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
            logger.info(f"Results uploaded for {scan_id}")
        else:
            logger.error(f"Failed to upload results for {scan_id}")

    # ── scanners ─────────────────────────────────────────────────────
    def scan_apt_packages(self) -> Dict:
        """Scan APT packages (Debian/Ubuntu)"""
        logger.info("Scanning APT packages...")
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

            logger.info(f"Found {len(packages)} APT packages")

        except subprocess.CalledProcessError as e:
            return {"error": f"dpkg-query failed: {e}", "packages": []}
        except Exception as e:
            return {"error": str(e), "packages": []}

        return {"packages": packages, "total_count": len(packages)}

    def scan_rpm_packages(self) -> Dict:
        """Scan RPM packages (RHEL/CentOS/Fedora)"""
        logger.info("Scanning RPM packages...")
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
                            "package_manager": "rpm",
                        }
                    )

            logger.info(f"Found {len(packages)} RPM packages")

        except subprocess.CalledProcessError as e:
            return {"error": f"rpm failed: {e}", "packages": []}
        except Exception as e:
            return {"error": str(e), "packages": []}

        return {"packages": packages, "total_count": len(packages)}

    def scan_docker_images(self) -> Dict:
        """Scan Docker images with Trivy for vulnerabilities"""
        logger.info("Scanning Docker images...")
        images: List[Dict] = []
        vulnerabilities: List[Dict] = []

        try:
            docker_check = subprocess.run(["which", "docker"], capture_output=True, text=True)
            if docker_check.returncode != 0:
                return {"error": "Docker not found", "images": [], "vulnerabilities": []}

            trivy_check = subprocess.run(["which", "trivy"], capture_output=True, text=True)
            if trivy_check.returncode != 0:
                return {
                    "error": "Trivy not found. Install via: apt-get install trivy",
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
                for line in result.stdout.strip().split("\n")
                if line.strip() and "<none>" not in line
            ]

            for image_name in image_names:
                logger.info(f"Scanning {image_name}...")

                try:
                    trivy_result = subprocess.run(
                        ["trivy", "image", "--format", "json", "--quiet", image_name],
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )

                    if trivy_result.returncode == 0 and trivy_result.stdout.strip():
                        trivy_data = json.loads(trivy_result.stdout)
                        image_vulns: List[Dict] = []
                        image_misconfigs: List[Dict] = []
                        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

                        for result_item in trivy_data.get("Results", []):
                            # Vulnerabilities
                            for vuln in result_item.get("Vulnerabilities", []):
                                sev = vuln.get("Severity", "UNKNOWN")
                                if sev in sev_counts:
                                    sev_counts[sev] += 1
                                image_vulns.append(
                                    {
                                        "cve_id": vuln.get("VulnerabilityID"),
                                        "severity": sev,
                                        "package_name": vuln.get("PkgName"),
                                        "package_version": vuln.get("InstalledVersion"),
                                        "description": (
                                            vuln.get("Description", "") or vuln.get("Title", "")
                                        )[:200],
                                        "fixed_version": vuln.get("FixedVersion"),
                                        "cvss_score": self._extract_cvss(vuln),
                                    }
                                )

                            # Misconfigurations from Trivy
                            for mc in result_item.get("Misconfigurations", []):
                                image_misconfigs.append(
                                    {
                                        "check_id": mc.get("ID", ""),
                                        "check_title": mc.get("Title", ""),
                                        "severity": mc.get("Severity", "UNKNOWN"),
                                        "status": mc.get("Status", "FAIL"),
                                        "resource": image_name,
                                        "description": (mc.get("Description", "") or "")[:500],
                                        "remediation": (mc.get("Resolution", "") or "")[:500],
                                        "source": "trivy",
                                    }
                                )

                        # Parse image name and tag
                        parts = image_name.rsplit(":", 1)
                        img_repo = parts[0]
                        img_tag = parts[1] if len(parts) > 1 else "latest"

                        images.append(
                            {
                                "image_name": img_repo,
                                "tag": img_tag,
                                "vulnerability_count": len(image_vulns),
                                "critical_count": sev_counts["CRITICAL"],
                                "high_count": sev_counts["HIGH"],
                                "medium_count": sev_counts["MEDIUM"],
                                "low_count": sev_counts["LOW"],
                            }
                        )
                        vulnerabilities.extend(image_vulns)
                        logger.info(
                            f"Found {len(image_vulns)} vulns, "
                            f"{len(image_misconfigs)} misconfigs in {image_name}"
                        )

                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout scanning {image_name}")
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse error for {image_name}: {e}")
                except Exception as e:
                    logger.error(f"Error scanning {image_name}: {e}")

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

    def scan_filesystem(self) -> Dict:
        """Scan mounted host filesystem with Trivy for vulnerabilities and misconfigs"""
        logger.info("Scanning host filesystem via Trivy...")
        vulnerabilities: List[Dict] = []
        misconfigurations: List[Dict] = []

        try:
            trivy_check = subprocess.run(["which", "trivy"], capture_output=True, text=True)
            if trivy_check.returncode != 0:
                return {"error": "Trivy not found", "vulnerabilities": [], "misconfigurations": []}

            # Scan /mnt/host which is the host root filesystem mounted read-only
            scan_path = "/mnt/host"
            if not Path(scan_path).exists():
                return {
                    "error": f"Host filesystem not mounted at {scan_path}",
                    "vulnerabilities": [],
                    "misconfigurations": [],
                }

            result = subprocess.run(
                [
                    "trivy", "fs", scan_path,
                    "--format", "json",
                    "--quiet",
                    "--scanners", "vuln,misconfig,secret",
                    "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0 and result.stdout.strip():
                trivy_data = json.loads(result.stdout)

                for result_item in trivy_data.get("Results", []):
                    target = result_item.get("Target", "")

                    # Vulnerabilities
                    for vuln in result_item.get("Vulnerabilities", []):
                        vulnerabilities.append(
                            {
                                "cve_id": vuln.get("VulnerabilityID"),
                                "severity": vuln.get("Severity", "UNKNOWN"),
                                "package_name": vuln.get("PkgName"),
                                "package_version": vuln.get("InstalledVersion"),
                                "description": (
                                    vuln.get("Description", "") or vuln.get("Title", "")
                                )[:200],
                                "fixed_version": vuln.get("FixedVersion"),
                                "cvss_score": self._extract_cvss(vuln),
                            }
                        )

                    # Misconfigurations
                    for mc in result_item.get("Misconfigurations", []):
                        misconfigurations.append(
                            {
                                "check_id": mc.get("ID", ""),
                                "check_title": mc.get("Title", ""),
                                "severity": mc.get("Severity", "UNKNOWN"),
                                "status": mc.get("Status", "FAIL"),
                                "resource": target,
                                "description": (mc.get("Description", "") or "")[:500],
                                "remediation": (mc.get("Resolution", "") or "")[:500],
                                "source": "trivy",
                            }
                        )

                    # Secrets (treat as critical misconfigurations)
                    for secret in result_item.get("Secrets", []):
                        misconfigurations.append(
                            {
                                "check_id": secret.get("RuleID", "SECRET"),
                                "check_title": secret.get("Title", "Secret Detected"),
                                "severity": "CRITICAL",
                                "status": "FAIL",
                                "resource": target,
                                "description": (secret.get("Match", "") or "")[:500],
                                "remediation": "Remove or rotate the exposed secret",
                                "source": "trivy-secret",
                            }
                        )

            logger.info(
                f"Filesystem scan: {len(vulnerabilities)} vulns, "
                f"{len(misconfigurations)} misconfigs"
            )

        except subprocess.TimeoutExpired:
            return {
                "error": "Filesystem scan timed out",
                "vulnerabilities": [],
                "misconfigurations": [],
            }
        except json.JSONDecodeError as e:
            return {
                "error": f"Failed to parse Trivy output: {e}",
                "vulnerabilities": [],
                "misconfigurations": [],
            }
        except Exception as e:
            return {"error": str(e), "vulnerabilities": [], "misconfigurations": []}

        return {
            "vulnerabilities": vulnerabilities,
            "misconfigurations": misconfigurations,
            "total_vulnerabilities": len(vulnerabilities),
            "total_misconfigurations": len(misconfigurations),
        }

    def scan_prowler(self) -> Dict:
        """Run Prowler for comprehensive security checks"""
        logger.info("Running Prowler security checks...")
        findings: List[Dict] = []

        try:
            prowler_check = subprocess.run(
                ["which", "prowler"], capture_output=True, text=True
            )
            if prowler_check.returncode != 0:
                return {"error": "Prowler not found", "misconfigurations": []}

            # Run prowler with JSON output to a temp dir
            prowler_out = self.output_dir / "prowler_tmp"
            prowler_out.mkdir(parents=True, exist_ok=True)

            result = subprocess.run(
                [
                    "prowler",
                    "docker",
                    "--output-directory", str(prowler_out),
                    "--output-formats", "json",
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                timeout=900,
            )

            # Parse output JSON files
            for json_file in prowler_out.glob("*.json"):
                try:
                    content = json_file.read_text()
                    # Prowler outputs JSONL (one JSON object per line)
                    for line in content.strip().split("\n"):
                        if not line.strip():
                            continue
                        try:
                            finding = json.loads(line)
                            findings.append(
                                {
                                    "check_id": finding.get("CheckID", ""),
                                    "check_title": finding.get("CheckTitle", ""),
                                    "severity": finding.get("Severity", "UNKNOWN").upper(),
                                    "status": finding.get("Status", "FAIL").upper(),
                                    "resource": finding.get("ResourceId", finding.get("ResourceArn", "")),
                                    "description": (
                                        finding.get("StatusExtended", "") or ""
                                    )[:500],
                                    "remediation": (
                                        finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
                                        if isinstance(finding.get("Remediation"), dict) else ""
                                    )[:500],
                                    "source": "prowler",
                                }
                            )
                        except json.JSONDecodeError:
                            continue
                except Exception as e:
                    logger.error(f"Error reading Prowler output {json_file}: {e}")

            logger.info(f"Prowler found {len(findings)} findings")

        except subprocess.TimeoutExpired:
            return {"error": "Prowler scan timed out", "misconfigurations": []}
        except Exception as e:
            return {"error": str(e), "misconfigurations": []}

        return {
            "misconfigurations": findings,
            "total_misconfigurations": len(findings),
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
        elif scan_type == "trivy-fs":
            return self.scan_filesystem()
        elif scan_type == "prowler":
            return self.scan_prowler()
        else:
            return {"error": f"Unknown scan type: {scan_type}"}

    # ── main loop ────────────────────────────────────────────────────
    def run(self):
        logger.info("Starting SBOM Agent...")

        max_attempts = 10
        base_delay = 5
        for attempt in range(1, max_attempts + 1):
            if self.register():
                break
            if attempt < max_attempts:
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "Registration attempt %d/%d failed; retrying in %ds...",
                    attempt, max_attempts, delay,
                )
                time.sleep(delay)
        else:
            logger.error("Failed to register. Exiting.")
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
                    logger.info(
                        f"Processing scan: {scan_id} (type: {scan_type})"
                    )

                    self.report_results(scan_id, "running", {})

                    try:
                        results = self.perform_scan(scan_type)

                        # Save output locally to shared volume
                        self._save_output(scan_type, results)

                        if "error" in results:
                            self.report_results(scan_id, "failed", results)
                        else:
                            self.report_results(scan_id, "completed", results)
                    except Exception as e:
                        logger.error(f"Scan failed: {e}")
                        self.report_results(scan_id, "failed", {"error": str(e)})

                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.fatal(f"Fatal error: {e}")
            raise


def start():
    try:
        agent = SBOMAgent()
        agent.run()
    except Exception as e:
        logger.fatal(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start()
