import os
import re
import json
import subprocess
from typing import List, Dict, Optional, Any
from rich import print
from rich.table import Table

from ..core.base_analyzer import BaseAnalyzer
from ..core.context import AnalysisContext
from ..models.package_info import AnalysisResult, PackageMetadata, ServiceMetadata, FileMetadata
from ..utils.plotting import TimeGraphPlot, ServiceNode as PlotServiceNode

# Helper to check if rpm is available
try:
    import rpm
    RPM_AVAILABLE = True
except ImportError:
    RPM_AVAILABLE = False


class RPMAnalyzer(BaseAnalyzer):
    """
    Analyzer for RPM-based systems (Fedora, CentOS, RHEL).
    """

    def detect(self, volume_path: str) -> bool:
        """Checks for the presence of rpm database."""
        return os.path.exists(os.path.join(volume_path, "var/lib/rpm"))

    def analyze_static(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs static analysis on an RPM-based system.
        """
        result = AnalysisResult()
        
        # RPM Static analysis basically queries the RPM DB.
        # This requires the python3-rpm binding or calling `rpm` command.
        # The binding might not work well if analyzing a different architecture or OS version DB.
        # But we will try to follow the original implementation logic.
        
        if not RPM_AVAILABLE:
            print("[Warning] 'rpm' python module not found. Static analysis might fail or be limited.")
            # Fallback to shelling out? For now, we stick to python logic if possible or notify user.
            
        print("Starting RPM Static Analysis...")
        self._analyze_rpm_db(context, result)
        
        self._print_table(result)
        self._save_output(context, result)
        return result

    def analyze_chroot(self, context: AnalysisContext) -> AnalysisResult:
        """
        Performs chroot analysis on an RPM-based system.
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

    def _analyze_rpm_db(self, context: AnalysisContext, result: AnalysisResult):
        if not RPM_AVAILABLE:
             return

        rpm_db_path = os.path.join(context.volume_path, "var/lib/rpm")
        # Initialize RPM transaction set with custom DB path
        rpm.addMacro("_dbpath", rpm_db_path)
        ts = rpm.TransactionSet()
        
        mi = ts.dbMatch()
        for hdr in mi:
            name = hdr['name']
            version = hdr['version']
            # release = hdr['release']
            
            # Find files (executables)
            files = hdr['filenames']
            exec_paths = [f for f in files if f.startswith(b'/usr/bin') or f.startswith(b'/bin')] # heuristic
            
            # Find services?
            # RPM content typically includes .service files in /usr/lib/systemd/system
            service_files = [f for f in files if f.endswith(b'.service')]
            
            # Create Package Entry
            # Decoding bytes to str
            name_str = name.decode('utf-8') if isinstance(name, bytes) else name
            version_str = version.decode('utf-8') if isinstance(version, bytes) else version
            
            pkg_meta = PackageMetadata(
                name=name_str,
                version=version_str,
                files=[FileMetadata(path=f.decode('utf-8', errors='ignore')) for f in exec_paths]
            )
            result.packages.append(pkg_meta)
            
            for svc in service_files:
                svc_str = os.path.basename(svc.decode('utf-8', errors='ignore'))
                # For static analysis, we might want to parse the service file to find executables too
                # But the file might be in /usr/lib/systemd/system which we can access via volume_path
                
                # Construct full path to service
                # We need to find where it is installed. RPM db 'filenames' gives full path usually.
                svc_full_path_bytes = svc
                svc_full_path = svc_full_path_bytes.decode('utf-8', errors='ignore')
                
                # Check if it exists on volume?
                # svc_full_path is absolute e.g. /usr/lib/systemd/system/foo.service
                # join with volume
                full_path_on_disk = os.path.join(context.volume_path, svc_full_path.lstrip('/'))
                
                exec_paths = []
                if os.path.exists(full_path_on_disk):
                    exec_paths = self._extract_executable_paths(full_path_on_disk)
                
                result.services.append(ServiceMetadata(
                    name=svc_str, 
                    associated_package=name_str,
                    version=version_str,
                    executables=exec_paths,
                    executable_names=[os.path.basename(p) for p in exec_paths]
                ))

    def _analyze_chroot_services(self, context: AnalysisContext, service_times: Dict[str, str], result: AnalysisResult):
        print("Starting Chroot Service Analysis...")
        systemd_path = self._get_systemd_path(context.volume_path)
        
        plotter = None
        if context.graphic_plot:
            plotter = TimeGraphPlot(systemd_path)

        # For RPM map service -> package is harder without the DB easily accessible or queryable by file
        # If we have RPM bindings we can query who owns a file.
        
        ts = None
        if RPM_AVAILABLE:
            rpm.addMacro("_dbpath", os.path.join(context.volume_path, "var/lib/rpm"))
            ts = rpm.TransactionSet()

        for service_name, time_str in service_times.items():
            # Find the package that owns this service file
            pkg_name = "unknown"
            version = "unknown"
            
            if ts:
                 # Query RPM DB for file
                 # Need full path of service file on the volume?
                 # RPM DB stores paths as they are installed (e.g. /usr/lib/systemd/system/foo.service)
                 # We need to find where the service file is.
                 service_path = self._find_service_path(context.volume_path, service_name)
                 if service_path:
                      # Strip volume path
                      rel_path = os.path.relpath(service_path, context.volume_path)
                      rel_path = "/" + rel_path.replace("\\", "/") # Linux path
                      
                      mi = ts.dbMatch('basenames', rel_path)
                      for hdr in mi:
                          pkg_name = hdr['name'].decode('utf-8')
                          version = hdr['version'].decode('utf-8')
                          break

            # Create/Get Package
            existing_pkg = next((p for p in result.packages if p.name == pkg_name), None)
            if not existing_pkg and pkg_name != "unknown":
                existing_pkg = PackageMetadata(name=pkg_name, version=version)
                result.packages.append(existing_pkg)
            
            # Extract executables
            exec_paths = []
            service_path = self._find_service_path(context.volume_path, service_name)
            if service_path:
                 exec_paths = self._extract_executable_paths(service_path)

            # Add Service
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
            "etc/systemd/system"
        ]
        for c in candidates:
            path = os.path.join(volume_path, c)
            if os.path.exists(path):
                return path
        return os.path.join(volume_path, "usr/lib/systemd/system")

    def _find_service_path(self, volume_path: str, service_name: str) -> Optional[str]:
         # Look in common systemd paths
         candidates = [
            "usr/lib/systemd/system",
             "etc/systemd/system",
             "lib/systemd/system"
         ]
         for c in candidates:
             path = os.path.join(volume_path, c, service_name)
             if os.path.exists(path):
                 return path
         return None

    def _print_table(self, result: AnalysisResult, show_time=False, service_times=None):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Version", style="dim")
        table.add_column("Services")
        if show_time:
            table.add_column("Time")
        
        for pkg in result.packages:
            services = [s.name for s in result.services if s.associated_package == pkg.name]
            
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

    def _extract_executable_paths(self, service_file_path: str) -> List[str]:
        # Helper to extract ExecStart/etc from a service file path
        paths = []
        if os.path.exists(service_file_path):
             with open(service_file_path, 'r', errors='ignore') as f:
                 content = f.read()
                 matches = re.findall(r'(Exec(?:Start|Stop|Pre)?=)(.+)', content)
                 for match in matches:
                     args = match[1].split()
                     path = args[0].strip()
                     if path.startswith('-'): path = path[1:]
                     # Return as found in service file (absolute usually)
                     paths.append(path)
        return paths
