import os
import json
from typing import List, Dict
from rich import print

from ..output_formatting.apt_outputs import static_mode_entry_info
from ..output_formatting.apt_outputs import static_mode_entry_service
from ..output_formatting.cdx import convert_to_cdx_apt_static_info
from ..output_formatting.cdx import convert_to_cdx_apt_static_service
from ..package_utils.apt_utils import apt_utils
from ..package_utils.cve_analyzer import CVEAnalyzer, check_nvdlib_available


class static_analysis_info_files:
    def __init__(self, volume_path: str, output_opt: str, cve_analysis: bool = False) -> None:
        try:
            self.volume_path: str = volume_path
            self.info_path: str = f"{self.volume_path}/var/lib/dpkg/info"
            self.output_opt: str = output_opt
            self.cve_analysis: bool = cve_analysis
            self.entries: List[static_mode_entry_info] = []
            self.packages: Dict[str, static_mode_entry_info] = {}
            self.utils = apt_utils(
                volume_path=self.volume_path,
                info_path=self.info_path,
                dpkg_path=f'{self.volume_path}/var/lib/dpkg/status'
            )
            self.static_analysis_fast_process()
        except Exception as e:
            print(f"Error in initialization: {e}")

    def static_analysis_fast_process(self):
        try:
            list_files = self.utils.list_info_files()
            for list_name in list_files:
                package_name = os.path.splitext(list_name)[0]
                version = self.utils.extract_version(package_name)
                service_files = self.utils.analyze_services(list_name)

                for service_name in service_files:
                    executable_paths = self.utils.extract_executable_paths(
                        service_name)
                    exec_names = [os.path.basename(path)
                                  for path in executable_paths]

                    entry = static_mode_entry_info(
                        Package=package_name,
                        ServiceName=service_name,
                        ExecutablePath=executable_paths,
                        ExecutableName=exec_names,
                        Version=version
                    )

                    if package_name not in self.packages:
                        self.packages[package_name] = entry

            # Run CVE analysis if enabled
            if self.cve_analysis:
                self._run_cve_analysis()

            self.utils.generate_table_static_info(packages=self.packages)
            self.save_packages_to_json()
        except Exception as e:
            print(f"Error in fast process: {e}")

    def _run_cve_analysis(self):
        """Run CVE analysis on collected packages."""
        if not check_nvdlib_available():
            print("[CVE Analysis] nvdlib not available. Install with: pip install nvdlib")
            return

        try:
            print("\n[CVE Analysis] Starting vulnerability scan...")
            analyzer = CVEAnalyzer()
            
            # Build package list for analysis
            pkg_list = [
                {'Package': name, 'Version': entry.Version}
                for name, entry in self.packages.items()
            ]
            
            # Run analysis
            cve_results = analyzer.analyze_packages(pkg_list)
            
            # Attach CVE results to entries
            for pkg_name, cves in cve_results.items():
                if pkg_name in self.packages and cves:
                    self.packages[pkg_name].Vulnerabilities = [
                        {
                            'cve_id': cve.cve_id,
                            'severity': cve.severity,
                            'score': cve.score
                        }
                        for cve in cves
                    ]
            
            # Print summary
            total_vulns = sum(len(cves) for cves in cve_results.values())
            critical = sum(
                1 for cves in cve_results.values() 
                for cve in cves if cve.severity == 'CRITICAL'
            )
            high = sum(
                1 for cves in cve_results.values() 
                for cve in cves if cve.severity == 'HIGH'
            )
            print(f"\n[CVE Analysis] Complete: {total_vulns} CVEs found ({critical} CRITICAL, {high} HIGH)")
            
        except Exception as e:
            print(f"[CVE Analysis] Error: {e}")

    def save_packages_to_json(self) -> None:
        try:
            serializable_packages = [
                entry.custom_output() for entry in self.packages.values()
            ]
            cdx_out = convert_to_cdx_apt_static_info(serializable_packages)
            with open(self.output_opt, 'w') as f:
                json.dump(cdx_out, f, indent=4)
            print(f"Successfully saved packages to {self.output_opt}")
        except Exception as e:
            if self.output_opt == '':
                pass
            else:
                print(f"Error saving packages to JSON: {e}")


class static_analysis_service_files:
    def __init__(self, volume_path: str, output_opt: str, cve_analysis: bool = False) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
        self.cve_analysis: bool = cve_analysis
        if os.path.exists(f"{self.volume_path}/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "lib/systemd/system")
        elif os.path.exists(f"{self.volume_path}/usr/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "usr/lib/systemd/system")
        else:
            self.systemd_path: str = os.path.join(
                self.volume_path, "etc/systemd/system")
        self.info_path = "/var/lib/dpkg/info"
        self.status_file_path = f'{self.volume_path}/var/lib/dpkg/status'
        self.utils = apt_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path,
            info_path=self.info_path,
            dpkg_path=self.status_file_path
        )
        self.service_analysis_process()

    def service_analysis_process(self):
        try:
            service_files = self.utils.analyze_services()
            entries = []

            package_versions = self.utils.extract_version()

            for service_file in service_files:
                executable_paths = self.utils.extract_executable_paths(
                    service_file)
                if not executable_paths:
                    continue

                info_files = self.utils.analyze_info(
                    exec_paths=executable_paths,
                    package_versions=package_versions
                )
                for package_name, version in info_files.items():
                    exec_names_set = {os.path.basename(
                        path) for path in executable_paths}

                    entry = static_mode_entry_service(
                        Package=package_name,
                        Version=version,
                        ServiceName=service_file,
                        ExecutablePath=list(executable_paths),
                        ExecutableNames=list(exec_names_set)
                    )
                    entries.append(entry)
            if not entries:
                print("No entries found for service analysis.")
                return
            combined_entries = static_mode_entry_service.combine_entries(
                entries)
            
            # Run CVE analysis if enabled
            if self.cve_analysis:
                combined_entries = self._run_cve_analysis(combined_entries)

            self.generate_output(combined_entries)

        except Exception as e:
            print(f"Service Process Error: {e}")

    def _run_cve_analysis(self, entries: List[static_mode_entry_service]) -> List[static_mode_entry_service]:
        """Run CVE analysis on collected packages."""
        if not check_nvdlib_available():
            print("[CVE Analysis] nvdlib not available. Install with: pip install nvdlib")
            return entries

        try:
            print("\n[CVE Analysis] Starting vulnerability scan...")
            analyzer = CVEAnalyzer()
            
            # Build package list for analysis
            pkg_list = [
                {'Package': entry.Package, 'Version': entry.Version}
                for entry in entries if entry.Package
            ]
            
            # Run analysis
            cve_results = analyzer.analyze_packages(pkg_list)
            
            # Attach CVE results to entries
            for entry in entries:
                if entry.Package in cve_results:
                    cves = cve_results[entry.Package]
                    if cves:
                        entry.Vulnerabilities = [
                            {
                                'cve_id': cve.cve_id,
                                'severity': cve.severity,
                                'score': cve.score
                            }
                            for cve in cves
                        ]
            
            # Print summary
            total_vulns = sum(len(cves) for cves in cve_results.values())
            critical = sum(
                1 for cves in cve_results.values() 
                for cve in cves if cve.severity == 'CRITICAL'
            )
            high = sum(
                1 for cves in cve_results.values() 
                for cve in cves if cve.severity == 'HIGH'
            )
            print(f"\n[CVE Analysis] Complete: {total_vulns} CVEs found ({critical} CRITICAL, {high} HIGH)")
            
        except Exception as e:
            print(f"[CVE Analysis] Error: {e}")
        
        return entries

    def generate_output(
            self, entries: List[static_mode_entry_service]) -> None:
        try:
            if not entries:
                print("No entries to display.")
                return

            if self.output_opt == '':
                self.utils.generate_table_static_service(entries)
            else:
                with open(self.output_opt, 'w+') as outfile:
                    out_entry = []
                    for entry in entries:
                        if entry.Package:
                            entry_json = entry.json()
                            out_entry.append(entry_json)
                    cdx_output = convert_to_cdx_apt_static_service(out_entry)
                    outfile.write(json.dumps(cdx_output))

                print(f"Output written to {self.output_opt}")
                self.utils.generate_table_static_service(entries)

        except Exception as e:
            print(f"Error generating output: {e}")


class apt_static_analysis:

    def __init__(
            self, volume_path: str, process_opt: str, output: str, cve_analysis: bool = False) -> None:
        self.volume_path: str = volume_path
        self.process_opt: str = process_opt
        self.output: str = output
        self.cve_analysis: bool = cve_analysis
        self.main_process()

    def main_process(self):
        try:
            if self.process_opt == "info":
                static_analysis_info_files(
                    volume_path=self.volume_path, 
                    output_opt=self.output,
                    cve_analysis=self.cve_analysis
                )
            elif self.process_opt == "service":
                static_analysis_service_files(
                    volume_path=self.volume_path, 
                    output_opt=self.output,
                    cve_analysis=self.cve_analysis
                )
            else:
                print("Invalid process option. Choose 'info' or 'service'.")
        except Exception as e:
            print(f"An error occurred during the main process: {e}")
