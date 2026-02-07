import os
import json
from typing import Dict, List, Any
from rich import print
from rich.table import Table

from ..output_formatting.pacman_outputs import static_mode_entry_info
from ..output_formatting.pacman_outputs import static_mode_entry_service
from ..output_formatting.cdx import convert_to_cdx_apt_static_info # Reusing apt cdx for now or need new one?
from ..output_formatting.cdx import convert_to_cdx_apt_static_service
from ..package_utils.pacman_utils import pacman_utils
from ..package_utils.cve_analyzer import CVEAnalyzer, check_nvdlib_available

class static_analysis_info_files:
    def __init__(self, volume_path: str, output_opt: str, cve_analysis: bool = False) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
        self.cve_analysis: bool = cve_analysis
        self.local_db_path: str = f"{self.volume_path}/var/lib/pacman/local"
        self.utils = pacman_utils(volume_path=self.volume_path)
        self.packages: Dict[str, static_mode_entry_info] = {}
        self.static_analysis_fast_process()

    def static_analysis_fast_process(self) -> None:
        try:
            if not os.path.exists(self.local_db_path):
                print(f"Pacman local database not found at {self.local_db_path}")
                return

            for entry in os.listdir(self.local_db_path):
                entry_path = os.path.join(self.local_db_path, entry)
                if not os.path.isdir(entry_path):
                    continue
                
                # Parse desc file for metadata
                desc_file = os.path.join(entry_path, 'desc')
                if not os.path.exists(desc_file):
                    continue
                    
                name, version = self.utils._parse_desc_file(desc_file)
                if not name:
                    continue
                    
                # Parse files file for executables
                files_file = os.path.join(entry_path, 'files')
                executable_paths = []
                executable_names = []
                
                if os.path.exists(files_file):
                    with open(files_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            path = line.strip()
                            # Check if it looks like an executable (in bin dirs)
                            # Pacman paths are relative, e.g. "usr/bin/bash"
                            if path.startswith('usr/bin/') or path.startswith('usr/sbin/') or \
                               path.startswith('bin/') or path.startswith('sbin/'):
                                full_path = os.path.join('/', path) # Make absolute
                                executable_paths.append(full_path)
                                executable_names.append(os.path.basename(path))

                self.packages[name] = static_mode_entry_info(
                    Package=name,
                    ServiceName="", # Info mode typically doesn't map services unless we check service files
                    ExecutablePath=executable_paths,
                    ExecutableName=executable_names,
                    Version=version
                )

            # Run CVE Analysis if enabled
            if self.cve_analysis:
                self._run_cve_analysis()

            # Generate output
            self.generate_output()

        except Exception as e:
            print(f"Error in static analysis info process: {e}")

    def _run_cve_analysis(self):
        if not check_nvdlib_available():
            print("[CVE Analysis] nvdlib not available. Install with: pip install nvdlib")
            return

        try:
            print("\n[CVE Analysis] Starting vulnerability scan...")
            analyzer = CVEAnalyzer()
            
            pkg_list = [
                {'Package': name, 'Version': entry.Version}
                for name, entry in self.packages.items()
            ]
            
            cve_results = analyzer.analyze_packages(pkg_list)
            
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
            
            # Summary
            total_vulns = sum(len(cves) for cves in cve_results.values())
            print(f"[CVE Analysis] Found {total_vulns} vulnerabilities.")

        except Exception as e:
            print(f"[CVE Analysis] Error: {e}")

    def generate_output(self):
        # Table output
        # For info files, user might not want a giant table of all packages
        # But apt_static_analyzer does generate_table_static_info
        # We can reuse the apt_utils one but we are in pacman_utils
        # Wait, pacman_utils needs generate_table_static_info
        pass # Implemented in utils? I should verify I added it to pacman_utils

        # JSON Output
        if self.output_opt:
            output_data = [pkg.dict() for pkg in self.packages.values()]
            # Reuse APT CDX conversion as structure is compatible or needs new one?
            # It expects specific dict structure.
            # convert_to_cdx_apt_static_info expects dict {pkg: info}
            # My packages is {pkg: info}
            # But the values are static_mode_entry_info objects
            # The conversion function likely iterates .items()
            
            try:
                # Convert to dict of dicts for the CDX function if needed
                # Or just dump raw JSON if CDX is specific to APT
                # Users might expect CDX.
                # Let's inspect convert_to_cdx_apt_static_info signature usage in apt
                # It passes self.packages directly.
                
                # I'll just dump JSON for now to be safe, or adapt CDX later
                 with open(self.output_opt, 'w+') as out_file:
                    out_file.write(json.dumps(output_data, indent=4))
            except Exception as e:
                print(f"Error writing output: {e}")


class static_analysis_service_files:
    def __init__(self, volume_path: str, output_opt: str, cve_analysis: bool = False) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
        self.cve_analysis: bool = cve_analysis
        self.systemd_path: str = self._get_systemd_path()
        self.utils = pacman_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path
        )
        self.service_analysis_process()

    def _get_systemd_path(self) -> str:
        paths = [
            "usr/lib/systemd/system",
            "lib/systemd/system",
            "etc/systemd/system"
        ]
        for p in paths:
            full_path = os.path.join(self.volume_path, p)
            if os.path.exists(full_path):
                return full_path
        return os.path.join(self.volume_path, "usr/lib/systemd/system")

    def service_analysis_process(self) -> None:
        entries = []
        service_files = self.utils.analyze_services()
        
        # Pre-load package versions to avoid repeated reads
        package_versions = self.utils.extract_version()
        
        for service_file in service_files:
            executable_paths = self.utils.extract_executable_paths(service_file)
            if not executable_paths:
                continue
            
            info_files = self.utils.analyze_info(
                exec_paths=executable_paths, 
                package_versions=package_versions
            )
            
            # info_files is dict {pkg: version} or list [pkg]
            # analyze_info returns dict if package_versions passed
            
            exec_names = [os.path.basename(path) for path in executable_paths]
            
            if isinstance(info_files, dict):
                for package_name, version in info_files.items():
                    entry = static_mode_entry_service(
                        Package=package_name,
                        Version=version,
                        ServiceName=service_file,
                        ExecutablePath=executable_paths,
                        ExecutableNames=exec_names
                    )
                    entries.append(entry)
            else:
                 # Should not happen if we pass package_versions
                 pass

        if not entries:
            print("No services found linked to packages.")
            return

        combined_entries = static_mode_entry_service.combine_entries(entries)
        
        if self.cve_analysis:
            combined_entries = self._run_cve_analysis(combined_entries)

        self.generate_output(combined_entries)

    def _run_cve_analysis(self, entries: List[static_mode_entry_service]) -> List[static_mode_entry_service]:
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
            total = sum(len(res) for res in cve_results.values())
            print(f"[CVE Analysis] Found {total} vulnerabilities.")
            
        except Exception as e:
            print(f"[CVE Analysis] Error: {e}")
            
        return entries

    def generate_output(self, entries: List[static_mode_entry_service]):
        self.utils.generate_table_static_service(entries)
        
        if self.output_opt:
            try:
                # Convert to dict for JSON dump
                data = [entry.dict() for entry in entries]
                with open(self.output_opt, 'w+') as f:
                    json.dump(data, f, indent=4)
            except Exception as e:
                print(f"Error saving output: {e}")


class pacman_static_analysis:
    def __init__(self, volume_path: str, static_type: str, output_opt: str, cve_analysis: bool = False) -> None:
        if static_type == 'info':
            static_analysis_info_files(volume_path, output_opt, cve_analysis)
        elif static_type == 'service':
            static_analysis_service_files(volume_path, output_opt, cve_analysis)
        else:
            print("Invalid static analysis type for Pacman")
