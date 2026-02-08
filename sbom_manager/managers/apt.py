import os
import re
import json
import subprocess
from typing import List, Dict, Optional, Any, Set
from rich import print
from rich.table import Table

from ..core.base_analyzer import BaseAnalyzer
from ..core.context import AnalysisContext
from ..models.package_info import AnalysisResult, PackageMetadata, ServiceMetadata, FileMetadata
from ..utils.cve import CVEAnalyzer, check_nvdlib_available
from ..utils.plotting import TimeGraphPlot, ServiceNode as PlotServiceNode

class APTAnalyzer(BaseAnalyzer):
    """
    Analyzer for Debian/Ubuntu based systems using APT/DPKG.
    """

    def detect(self, volume_path: str) -> bool:
        """Checks for the presence of dpkg status file."""
        return os.path.exists(os.path.join(volume_path, "var/lib/dpkg/status"))

    def analyze_static(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs static analysis on an APT-based system.
        """
        result = AnalysisResult()
        
        info_path = os.path.join(context.volume_path, "var/lib/dpkg/info")
        dpkg_status_path = os.path.join(context.volume_path, "var/lib/dpkg/status")
        
        if context.static_type == "info":
             self._analyze_static_info(context, info_path, dpkg_status_path, result)
        elif context.static_type == "service":
             self._analyze_static_service(context, info_path, dpkg_status_path, result)
        else:
            print(f"Unknown static type: {context.static_type}, defaulting to info analysis.")
            self._analyze_static_info(context, info_path, dpkg_status_path, result)
            
        return result

    def analyze_chroot(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs chroot analysis on an APT-based system.
        """
        result = AnalysisResult()
        
        # 1. Bootup Analysis (Mounts and systemd-analyze)
        # Note: This requires sudo and safe environment.
        # We will assume the user knows what they are doing as per original code.
        
        try:
             self._mount_filesystems(context.volume_path)
             
             # Generate SVG
             svg_path = "SVG/bootup.svg"
             os.makedirs("SVG", exist_ok=True)
             
             with open(svg_path, "w+") as f:
                 subprocess.run(
                     ["sudo", "chroot", context.volume_path, "systemd-analyze", "plot"],
                     check=True, stdout=f
                 )
             
             # Extract times
             service_times = self._extract_service_times(svg_path)
             
             # Map services to packages
             self._analyze_chroot_services(context, service_times, result)
             
        except subprocess.CalledProcessError as e:
            print(f"Error during chroot analysis: {e}")
        except Exception as e:
            print(f"Unexpected error during chroot analysis: {e}")
            
        return result

    # --- Internal Analysis Methods ---

    def _analyze_static_info(self, context: AnalysisContext, info_path: str, dpkg_status_path: str, result: AnalysisResult):
        print("Starting Static Info Analysis...")
        list_files = self._list_info_files(info_path)
        
        for list_name in list_files:
            package_name = os.path.splitext(list_name)[0]
            version = self._extract_version(dpkg_status_path, package_name)
            
            # Find associated services
            service_files = self._analyze_associated_services(info_path, list_name)
            
            # Find executables
            all_exec_paths = []
            for service_name in service_files:
                systemd_path = self._get_systemd_path(context.volume_path)
                exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, service_name)
                all_exec_paths.extend(exec_paths)

            # Create Package Entry
            pkg_meta = PackageMetadata(
                name=package_name,
                version=version,
                files=[FileMetadata(path=p) for p in all_exec_paths] # Storing exec paths as files for now
            )
            
            # Add vulnerabilities
            if context.cve_analysis:
                self._enrich_with_cve(pkg_meta)

            result.packages.append(pkg_meta)
            
            # Create Service Entries
            for s_name in service_files:
                exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, s_name)
                svc_meta = ServiceMetadata(
                    name=s_name,
                    associated_package=package_name,
                    version=version,
                    executables=exec_paths,
                    executable_names=[os.path.basename(p) for p in exec_paths]
                )
                result.services.append(svc_meta)
        
        self._print_table(result)
        self._save_output(context, result)

    def _analyze_static_service(self, context: AnalysisContext, info_path: str, dpkg_status_path: str, result: AnalysisResult):
        print("Starting Static Service Analysis...")
        versions = self._extract_version(dpkg_status_path) # Get all versions
        
        services_to_process = []
        if context.init_system:
             # Use the provided init system analyzer
             # It returns ServiceMetadata objects with executables already parsed
             services_to_process = context.init_system.get_all_services(context.volume_path)
        else:
             # Fallback to internal systemd logic (legacy support)
             systemd_path = self._get_systemd_path(context.volume_path)
             service_files = self._list_service_files(systemd_path)
             for sf in service_files:
                 exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, sf)
                 services_to_process.append(ServiceMetadata(
                     name=sf,
                     executables=exec_paths,
                     executable_names=[os.path.basename(p) for p in exec_paths]
                 ))

        for svc in services_to_process:
            exec_paths = svc.executables
            if not exec_paths:
                continue
                
            # Find which package owns these executables
            owning_packages = self._find_owning_packages(info_path, exec_paths, context.volume_path)
            
            for pkg_name in owning_packages:
                version = versions.get(pkg_name, "unknown")
                
                # Check if package already exists in result
                existing_pkg = next((p for p in result.packages if p.name == pkg_name), None)
                if not existing_pkg:
                    existing_pkg = PackageMetadata(name=pkg_name, version=version)
                    if context.cve_analysis:
                        self._enrich_with_cve(existing_pkg)
                    result.packages.append(existing_pkg)
                
                # Add file metadata if not present
                for ep in exec_paths:
                    if not any(f.path == ep for f in existing_pkg.files):
                        existing_pkg.files.append(FileMetadata(path=ep))

                # Add Service
                if not any(s.name == svc.name for s in result.services):
                    # Update service metadata with package info
                    svc.associated_package = pkg_name
                    svc.version = version
                    result.services.append(svc)

        self._print_table(result)
        self._save_output(context, result)

    def _analyze_chroot_services(self, context: AnalysisContext, service_times: Dict[str, str], result: AnalysisResult):
        print("Starting Chroot Service Analysis...")
        systemd_path = self._get_systemd_path(context.volume_path)
        info_path = os.path.join(context.volume_path, "var/lib/dpkg/info")
        dpkg_status_path = os.path.join(context.volume_path, "var/lib/dpkg/status")
        
        plotter = None
        if context.graphic_plot:
            plotter = TimeGraphPlot(systemd_path)

        for service_name, time_str in service_times.items():
            exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, service_name)
            if not exec_paths:
                continue
            
            owning_packages = self._find_owning_packages(info_path, exec_paths, context.volume_path)
            
            for pkg_name in owning_packages:
                version = self._extract_version(dpkg_status_path, pkg_name)
                
                 # Check if package already exists in result
                existing_pkg = next((p for p in result.packages if p.name == pkg_name), None)
                if not existing_pkg:
                    existing_pkg = PackageMetadata(name=pkg_name, version=version)
                    if context.cve_analysis:
                        self._enrich_with_cve(existing_pkg)
                    result.packages.append(existing_pkg)
                
                # Add service info
                svc_meta = ServiceMetadata(
                    name=service_name, 
                    associated_package=pkg_name,
                    version=version,
                    execution_time=time_str,
                    executables=exec_paths,
                    executable_names=[os.path.basename(p) for p in exec_paths]
                )
                # Hack to store time in result metadata for now or extend model
                # Ideally ServiceMetadata has 'properties' dict
                # For now, let's just keep track of it for plotting
                result.services.append(svc_meta)

                if plotter:
                    # Parse time string "123ms" -> 123
                    ms = int(''.join(filter(str.isdigit, time_str)))
                    # Get before/after
                    deps = plotter.parse_service_file(service_name)
                    plotter.add_node(PlotServiceNode(
                        name=service_name,
                        execution_time=ms,
                        before=deps.get("Before", []),
                        after=deps.get("After", []),
                        package=pkg_name
                    ))

        self._print_table(result, show_time=True, service_times=service_times)
        
        if plotter:
            plotter.plot_graph()
            
        self._save_output(context, result)

    # --- Helper Methods (Ported from apt_utils.py) ---

    def _get_systemd_path(self, volume_path: str) -> str:
        candidates = [
            "lib/systemd/system",
            "usr/lib/systemd/system",
            "etc/systemd/system"
        ]
        for c in candidates:
            path = os.path.join(volume_path, c)
            if os.path.exists(path):
                return path
        return os.path.join(volume_path, "etc/systemd/system") # Default fallback

    def _list_info_files(self, info_path: str) -> List[str]:
        if not os.path.exists(info_path):
             return []
        return [f for f in os.listdir(info_path) if f.endswith(".list")]

    def _list_service_files(self, systemd_path: str) -> List[str]:
        if not os.path.exists(systemd_path):
            return []
        return [f for f in os.listdir(systemd_path) if f.endswith(".service")]

    def _extract_version(self, dpkg_status_path: str, package_name: Optional[str] = None) -> Any:
        # Simplified version of apt_utils.extract_version
        versions = {}
        try:
            with open(dpkg_status_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_pkg = None
                for line in f:
                    line = line.strip()
                    if line.startswith('Package:'):
                        current_pkg = line.split(': ')[1]
                        versions[current_pkg] = ""
                    elif line.startswith('Version:') and current_pkg:
                        versions[current_pkg] = line.split(': ')[1]
                    elif line == '' and current_pkg:
                        current_pkg = None
        except Exception as e:
            print(f"Error reading dpkg status: {e}")
            return "" if package_name else {}

        if package_name:
            return versions.get(package_name, "")
        return versions

    def _analyze_associated_services(self, info_path: str, list_name: str) -> List[str]:
        # Checks if .list file contains .service files
        services = []
        path = os.path.join(info_path, list_name)
        if os.path.exists(path):
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    if re.search(r'\.service\b(?![.\w])', line):
                        services.append(line.strip().split('/')[-1]) # just the filename
        return services

    def _extract_executable_paths(self, volume_path: str, systemd_path: str, service_name: str) -> List[str]:
        paths = []
        # Try local systemd path first (relative to volume)
        service_path = os.path.join(systemd_path, service_name)
        
        content = ""
        if os.path.exists(service_path):
             with open(service_path, 'r') as f:
                 content = f.read()
        else:
            # Try searching in volume if not found in systemd dir ???
             pass
        
        if content:
             matches = re.findall(r'(Exec(?:Start|Stop|Pre)?=)(.+)', content)
             for match in matches:
                 args = match[1].split()
                 path = args[0].strip()
                 # Clean up path modifiers like -
                 if path.startswith('-'): path = path[1:]
                 
                 # Resolve path relative to volume?
                 # APT Utils logic was checking if os.path.isfile(path) which implies running on host?
                 # If analyzing a mounted volume, we should prepend volume_path to check existence?
                 # The original code seemed to define logic for both.
                 # Let's try to resolve it.
                 
                 full_path = path
                 if not path.startswith(volume_path) and not path.startswith('/'):
                      # Relative? Unlikely for ExecStart
                      pass
                 
                 # Construct potential full path on mounted volume
                 potential_path = os.path.normpath(os.path.join(volume_path, path.lstrip('/')))
                 if os.path.exists(potential_path):
                     if os.path.islink(potential_path):
                         # resolve logic
                         paths.append(os.path.realpath(potential_path))
                     else:
                         paths.append(os.path.abspath(potential_path))
                 elif os.path.exists(path): # Check host path?
                      paths.append(os.path.abspath(path))
        
        return paths

    def _find_owning_packages(self, info_path: str, exec_paths: List[str], volume_path: str) -> List[str]:
        owners = []
        if not os.path.exists(info_path):
            return []
            
        normalized_exec_paths = []
        for ep in exec_paths:
            # Strip volume_path to get the absolute path as seen by the system
            # e.g., d:\mnt\usr\bin\foo -> /usr/bin/foo
            try:
                rel = os.path.relpath(ep, volume_path)
                # Ensure it starts with / for Linux-style paths in .list
                # On Windows relpath might use backslashes, need to ensure forward slashes for .list matching
                linux_path = "/" + rel.replace("\\", "/")
                normalized_exec_paths.append(linux_path)
            except ValueError:
                # ep is not relative to volume_path?
                normalized_exec_paths.append(ep)

        for f in os.listdir(info_path):
            if f.endswith('.list'):
                list_file_path = os.path.join(info_path, f)
                try:
                    with open(list_file_path, 'r', errors='ignore') as lf:
                        content = lf.read()
                        for target_path in normalized_exec_paths:
                            # .list files have one file per line usually, but we read whole content
                            # precise match ensures we don't match /usr/bin/foobar when looking for /usr/bin/foo
                            # But reading line by line is slow. 
                            # Check if valid path in content
                            
                            # Searching for exact line match is safest
                            # But content is a giant string.
                            # " \n/usr/bin/foo\n" logic?
                            if target_path in content:
                                owners.append(os.path.splitext(f)[0])
                                break
                except Exception:
                    continue
        return list(set(owners))

    def _enrich_with_cve(self, package: PackageMetadata):
        if not check_nvdlib_available():
            return
        # Use singleton or create new? Analyzer is lightweight.
        analyzer = CVEAnalyzer()
        cves = analyzer.lookup_cves(package.name, package.version)
        package.vulnerabilities = [
            {'cve_id': c.cve_id, 'severity': c.severity, 'score': c.score} 
            for c in cves
        ]

    def _print_table(self, result: AnalysisResult, show_time=False, service_times=None):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Version", style="dim")
        table.add_column("Services")
        table.add_column("Executables")
        if show_time:
            table.add_column("Time")
        table.add_column("CVEs", style="red")
        
        for pkg in result.packages:
            # Find services for this package
            services = [s.name for s in result.services if s.associated_package == pkg.name]
            execs = [f.path for f in pkg.files]
            
            cve_txt = f"{len(pkg.vulnerabilities)} CVEs" if pkg.vulnerabilities else "None"
            
            row = [
                pkg.name,
                pkg.version,
                "\n".join(services),
                "\n".join(execs)
            ]
            if show_time:
                # Find time for services
                times = []
                for s in services:
                    if service_times and s in service_times:
                        times.append(service_times[s])
                row.append("\n".join(times))
            
            row.append(cve_txt)
            table.add_row(*row)
            
        print(table)

    def _save_output(self, context: AnalysisContext, result: AnalysisResult):
        from ..output.writer import save_analysis_result
        save_analysis_result(context, result)

    def _mount_filesystems(self, volume_path: str):
        # Only run if distinct from / ??
        # Original code just ran sudo mount --bind
        dirs = ["bin", "lib", "lib64", "usr"]
        for d in dirs:
            src = os.path.join(volume_path, d)
            dst = f"/{d}"
            if os.path.exists(src):
                subprocess.run(["sudo", "mount", "--bind", src, dst], check=True)

    def _extract_service_times(self, svg_path: str) -> Dict[str, str]:
        pattern = re.compile(r'([^<>\n]+\.service) \((\d+ms)\)')
        service_times = {}
        if os.path.exists(svg_path):
            with open(svg_path, 'r') as file:
                for line in file:
                    match = re.search(pattern, line)
                    if match:
                        service_times[match.group(1)] = match.group(2)
        return service_times
