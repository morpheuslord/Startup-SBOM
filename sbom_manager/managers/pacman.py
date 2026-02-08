import os
import re
import json
import subprocess
from typing import List, Dict, Optional, Any, Tuple
from rich import print
from rich.table import Table

from ..core.base_analyzer import BaseAnalyzer
from ..core.context import AnalysisContext
from ..models.package_info import AnalysisResult, PackageMetadata, ServiceMetadata, FileMetadata
from ..utils.cve import CVEAnalyzer, check_nvdlib_available
from ..utils.plotting import TimeGraphPlot, ServiceNode as PlotServiceNode


class PacmanAnalyzer(BaseAnalyzer):
    """
    Analyzer for Arch Linux based systems using Pacman.
    """

    def detect(self, volume_path: str) -> bool:
        """Checks for the presence of pacman local database."""
        return os.path.exists(os.path.join(volume_path, "var/lib/pacman/local"))

    def analyze_static(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs static analysis on a Pacman-based system.
        """
        result = AnalysisResult()
        local_db_path = os.path.join(context.volume_path, "var/lib/pacman/local")
        
        if context.static_type == "info":
             self._analyze_static_info(context, local_db_path, result)
        elif context.static_type == "service":
             self._analyze_static_service(context, local_db_path, result)
        else:
            print(f"Unknown static type: {context.static_type}, defaulting to info analysis.")
            self._analyze_static_info(context, local_db_path, result)
            
        return result

    def analyze_chroot(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs chroot analysis on a Pacman-based system.
        """
        result = AnalysisResult()
        
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

    def _analyze_static_info(self, context: AnalysisContext, local_db_path: str, result: AnalysisResult):
        print("Starting Pacman Static Info Analysis...")
        
        if not os.path.exists(local_db_path):
             return

        for entry in os.listdir(local_db_path):
            entry_path = os.path.join(local_db_path, entry)
            if not os.path.isdir(entry_path):
                continue
            
            desc_file = os.path.join(entry_path, 'desc')
            if not os.path.exists(desc_file):
                continue
                
            name, version = self._parse_desc_file(desc_file)
            if not name:
                continue
            
            # Get executables from 'files'
            files_file = os.path.join(entry_path, 'files')
            exec_paths = self._extract_files_from_db(files_file)
            
            # Create Package Entry
            pkg_meta = PackageMetadata(
                name=name,
                version=version,
                files=[FileMetadata(path=p) for p in exec_paths]
            )
            
            if context.cve_analysis:
                self._enrich_with_cve(pkg_meta)
                
            result.packages.append(pkg_meta)
            
            # Pacman 'info' mode in original didn't map services, but we can if we want.
            # Original: ServiceName=""
            pass

        self._print_table(result)
        self._save_output(context, result)

    def _analyze_static_service(self, context: AnalysisContext, local_db_path: str, result: AnalysisResult):
        print("Starting Pacman Static Service Analysis...")
        systemd_path = self._get_systemd_path(context.volume_path)
        service_files = self._list_service_files(systemd_path)
        
        # Pre-load package versions?
        # We can look them up on demand or cache.
        
        for service_file in service_files:
            exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, service_file)
            if not exec_paths:
                continue
                
            # Find owning packages
            owning_packages = self._find_owning_packages(local_db_path, exec_paths, context.volume_path)
            
            for pkg_name in owning_packages:
                # Get version from db
                # We need to find the specific dir for this package or scan all (slow)
                # Optimization: map pkg_name to version first?
                version = self._get_package_version(local_db_path, pkg_name)
                
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
                if not any(s.name == service_file for s in result.services):
                    result.services.append(ServiceMetadata(
                        name=service_file, 
                        associated_package=pkg_name,
                        version=version,
                        executables=exec_paths,
                        executable_names=[os.path.basename(p) for p in exec_paths]
                    ))

        self._print_table(result)
        self._save_output(context, result)

    def _analyze_chroot_services(self, context: AnalysisContext, service_times: Dict[str, str], result: AnalysisResult):
        print("Starting Chroot Service Analysis...")
        systemd_path = self._get_systemd_path(context.volume_path)
        local_db_path = os.path.join(context.volume_path, "var/lib/pacman/local")
        
        plotter = None
        if context.graphic_plot:
            plotter = TimeGraphPlot(systemd_path)

        for service_name, time_str in service_times.items():
            exec_paths = self._extract_executable_paths(context.volume_path, systemd_path, service_name)
            if not exec_paths:
                 continue
            
            owning_packages = self._find_owning_packages(local_db_path, exec_paths, context.volume_path)
            
            for pkg_name in owning_packages:
                version = self._get_package_version(local_db_path, pkg_name)
                
                existing_pkg = next((p for p in result.packages if p.name == pkg_name), None)
                if not existing_pkg:
                    existing_pkg = PackageMetadata(name=pkg_name, version=version)
                    if context.cve_analysis:
                        self._enrich_with_cve(existing_pkg)
                    result.packages.append(existing_pkg)
                
                result.services.append(ServiceMetadata(
                    name=service_name, 
                    associated_package=pkg_name,
                    version=version,
                    execution_time=time_str,
                    executables=exec_paths,
                    executable_names=[os.path.basename(p) for p in exec_paths]
                ))
                
                if plotter:
                    ms = int(''.join(filter(str.isdigit, time_str)))
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

    # --- Helper Methods ---

    def _get_systemd_path(self, volume_path: str) -> str:
        candidates = [
            "usr/lib/systemd/system",
            "lib/systemd/system",
            "etc/systemd/system"
        ]
        for c in candidates:
            path = os.path.join(volume_path, c)
            if os.path.exists(path):
                return path
        return os.path.join(volume_path, "usr/lib/systemd/system")

    def _list_service_files(self, systemd_path: str) -> List[str]:
        if not os.path.exists(systemd_path):
            return []
        return [f for f in os.listdir(systemd_path) if f.endswith(".service")]

    def _parse_desc_file(self, filepath: str) -> Tuple[Optional[str], Optional[str]]:
        name = None
        version = None
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    line = line.strip()
                    if line == '%NAME%':
                        if i + 1 < len(lines):
                            name = lines[i+1].strip()
                    elif line == '%VERSION%':
                        if i + 1 < len(lines):
                            version = lines[i+1].strip()
        except Exception:
            pass
        return name, version

    def _extract_files_from_db(self, files_file: str) -> List[str]:
        # Returns absolute paths (heuristic for bin paths)
        paths = []
        if os.path.exists(files_file):
            try:
                with open(files_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        path = line.strip()
                        # Pacman paths are relative e.g. usr/bin/bash
                        if path.startswith('usr/bin/') or path.startswith('usr/sbin/') or \
                           path.startswith('bin/') or path.startswith('sbin/'):
                            paths.append("/" + path)
            except Exception:
                pass
        return paths

    def _extract_executable_paths(self, volume_path: str, systemd_path: str, service_name: str) -> List[str]:
        paths = []
        service_path = os.path.join(systemd_path, service_name)
        
        content = ""
        if os.path.exists(service_path):
             with open(service_path, 'r') as f:
                 content = f.read()
        
        if content:
             matches = re.findall(r'(Exec(?:Start|Stop|Pre)?=)(.+)', content)
             for match in matches:
                 args = match[1].split()
                 path = args[0].strip()
                 if path.startswith('-'): path = path[1:]
                 
                 # Logic to handle volume path?
                 # Basically same as APT
                 
                 # Check if path is absolute relative to root
                 if path.startswith('/'):
                     paths.append(path) # keep original
                 else:
                     pass
        return paths

    def _find_owning_packages(self, local_db_path: str, exec_paths: List[str], volume_path: str) -> List[str]:
        owners = []
        if not os.path.exists(local_db_path):
            return []

        # Prepare exec_paths: strip / at start to match pacman DB format (e.g. usr/bin/foo)
        # Note: exec_paths from service files are usually absolute /usr/bin/foo
        # We need to strip leading /
        
        targets = set()
        for ep in exec_paths:
            # We assume ep is absolute system path (e.g. /usr/bin/foo)
            # If it's a volume path (e.g. /mnt/usr/bin/foo), we need to strip volume first.
            rel = ep
            try:
                if ep.startswith(volume_path):
                    rel = os.path.relpath(ep, volume_path)
                    
                # Ensure Linux separators and strip leading /
                rel = rel.replace("\\", "/").lstrip("/")
                targets.add(rel)
            except ValueError:
                pass

        for entry in os.listdir(local_db_path):
            entry_path = os.path.join(local_db_path, entry)
            if not os.path.isdir(entry_path): continue
            
            files_file = os.path.join(entry_path, 'files')
            if not os.path.exists(files_file): continue
            
            try:
                with open(files_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Check if any target is in content
                    # content is list of paths
                    # Simple check 'path\n' in content?
                    # Or iteration
                    
                    found = False
                    for t in targets:
                        # Pacman files list: each line is a path. exact match.
                        if t in content.splitlines():
                            desc_file = os.path.join(entry_path, 'desc')
                            name, _ = self._parse_desc_file(desc_file)
                            if name:
                                owners.append(name)
                                found = True
                                break
                    # if found: break? No, iterate all packages? 
                    # A file is owned by one package usually.
            except Exception:
                pass
                
        return list(set(owners))

    def _get_package_version(self, local_db_path: str, package_name: str) -> str:
        # Search for directory starting with package_name-version-release?
        # Or iterate all. Iterate all is safer.
        for entry in os.listdir(local_db_path):
            entry_path = os.path.join(local_db_path, entry)
            if not os.path.isdir(entry_path): continue
            
            desc_file = os.path.join(entry_path, 'desc')
            if os.path.exists(desc_file):
                name, version = self._parse_desc_file(desc_file)
                if name == package_name:
                    return version or "unknown"
        return "unknown"

    def _enrich_with_cve(self, package: PackageMetadata):
        if not check_nvdlib_available():
            return
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
        if show_time:
            table.add_column("Time")
        table.add_column("CVEs", style="red")
        
        for pkg in result.packages:
            services = [s.name for s in result.services if s.associated_package == pkg.name]
            execs = [f.path for f in pkg.files]
            
            cve_txt = f"{len(pkg.vulnerabilities)} CVEs" if pkg.vulnerabilities else "None"
            
            row = [
                pkg.name,
                pkg.version,
                "\n".join(services)
            ]
            if show_time:
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
