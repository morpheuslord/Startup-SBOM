import os
import re
import json
import subprocess
from rich import print
from typing import Dict, List

from ..output_formatting.pacman_outputs import chroot_mode_entry_service
from ..output_formatting.time_plot import AptTimeGraphPlot # Reuse time plot logic
from ..output_formatting.cdx import convert_to_cdx_apt_chroot # Reuse CDX logic
from ..package_utils.pacman_utils import pacman_utils
from ..package_utils.cve_analyzer import CVEAnalyzer, check_nvdlib_available


class pacman_chroot_analysis:
    def __init__(
            self,
            volume_path: str, output_opt: str, graphic_plot: bool, cve_analysis: bool = False) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
        self.graphic_plot: bool = graphic_plot
        self.cve_analysis: bool = cve_analysis
        
        self.info_path: str = f"{self.volume_path}/var/lib/pacman/local"
        self.extracted_info: Dict[str, str] = {}
        
        # Determine systemd path
        if os.path.exists(f"{self.volume_path}/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "lib/systemd/system")
        elif os.path.exists(f"{self.volume_path}/usr/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "usr/lib/systemd/system")
        else:
            self.systemd_path: str = os.path.join(
                self.volume_path, "etc/systemd/system")
                
        self.image_path = "SVG//bootup.svg"
        self.out_data: str = ""
        
        self.run_bootup_analysis()
        self.extract_service_times()
        self.service_analysis_process()

    def run_bootup_analysis(self) -> None:
        try:
            # Mount necessary directories
            # Pacman needs /var/lib/pacman for database access if we run pacman commands
            # But we are running systemd-analyze, which doesn't need pacman db
            # However, mapping services to packages later requires db access
            # We access db from python script outside chroot, so we don't strictly need it mapped inside?
            # But systemd-analyze needs /bin, /lib, /usr etc.
            
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/bin", "/bin"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/lib", "/lib"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/lib64", "/lib64"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/usr", "/usr"], check=True)
            
            # Create SVG directory if not exists
            if not os.path.exists("SVG"):
                os.makedirs("SVG")

            subprocess.run(
                [
                    "sudo",
                    "chroot",
                    self.volume_path,
                    "systemd-analyze",
                    "plot"
                ], check=True, stdout=open(self.image_path, "w+")
            )
        except subprocess.CalledProcessError as e:
            print("Error running bootup analysis:", e)
        except Exception as e:
             print(f"Error: {e}")

    def extract_service_times(self) -> None:
        if not os.path.exists(self.image_path):
            return

        pattern = re.compile(r'([^<>\n]+\.service) \((\d+ms)\)')
        service_times = {}

        with open(self.image_path, 'r') as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    service_name = match.group(1)
                    time = match.group(2)
                    service_times[service_name] = time

        self.extracted_info = service_times

    def service_analysis_process(self) -> None:
        entries = []
        utils = pacman_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path
        )
        
        # Pre-load package versions
        package_versions = utils.extract_version()
        
        for service_name, time in self.extracted_info.items():
            executable_paths = utils.extract_executable_paths(service_name)
            if not executable_paths:
                continue
            
            info_files = utils.analyze_info(
                exec_paths=executable_paths,
                package_versions=package_versions
            )
            
            exec_names = [os.path.basename(path) for path in executable_paths]
            
            # info_files is dict {pkg: version}
            for package_name, version in info_files.items():
                entry = chroot_mode_entry_service(
                    Package=package_name,
                    ServiceName=service_name,
                    ExecutablePath=executable_paths,
                    ExecutableNames=exec_names,
                    ExecutionTime=str(time),
                    Version=version
                )
                entries.append(entry)

        combined_entries = chroot_mode_entry_service.combine_entries(entries)

        # Run CVE Analysis
        if self.cve_analysis:
            combined_entries = self._run_cve_analysis(combined_entries)

        self.out_data = json.dumps([entry.dict()
                                   for entry in combined_entries], indent=4)
                                   
        # Generate CDX output
        cdx_data = convert_to_cdx_apt_chroot(self.out_data)
        
        if self.output_opt:
            try:
                with open(self.output_opt, 'w+') as out_file:
                    out_file.write(json.dumps(cdx_data))
            except Exception as e:
                print(f"Error writing to output file: {e}")
                
        utils.generate_table_chroot(entries=combined_entries)

        if self.graphic_plot:
            try:
                AptTimeGraphPlot(
                    service_files_path=self.systemd_path,
                    json_data=self.out_data
                )
            except Exception as e:
                print(f"Error plotting graph: {e}")

    def _run_cve_analysis(self, entries: List[chroot_mode_entry_service]) -> List[chroot_mode_entry_service]:
        if not check_nvdlib_available():
            print("[CVE Analysis] nvdlib not available")
            return entries
            
        try:
            print("\n[CVE Analysis] Starting vulnerability scan...")
            analyzer = CVEAnalyzer()
            pkg_list = [
                {'Package': entry.Package, 'Version': entry.Version}
                for entry in entries if entry.Package
            ]
            
            cve_results = analyzer.analyze_packages(pkg_list)
            
            for entry in entries:
                if entry.Package in cve_results:
                    cves = cve_results[entry.Package]
                    if cves:
                        entry.Vulnerabilities = [
                             {'cve_id': c.cve_id, 'severity': c.severity, 'score': c.score}
                             for c in cves
                        ]
            
            # Summary
            total = sum(len(cves) for cves in cve_results.values())
            print(f"[CVE Analysis] Found {total} vulnerabilities.")
            
        except Exception as e:
            print(f"[CVE Analysis] Error: {e}")
            
        return entries
