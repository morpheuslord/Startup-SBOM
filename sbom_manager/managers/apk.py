import os
import re
from typing import List, Dict, Optional, Any
from rich import print
from rich.table import Table

from ..core.base_analyzer import BaseAnalyzer
from ..core.context import AnalysisContext
from ..models.package_info import AnalysisResult, PackageMetadata, ServiceMetadata, FileMetadata
from ..utils.cve import CVEAnalyzer, check_nvdlib_available

class APKAnalyzer(BaseAnalyzer):
    """
    Analyzer for Alpine Linux (APK).
    """

    def detect(self, volume_path: str) -> bool:
        return os.path.exists(os.path.join(volume_path, "lib/apk/db/installed"))

    def analyze_static(self, context: AnalysisContext) -> AnalysisResult:
        result = AnalysisResult()
        print("Starting APK Static Analysis...")

        db_path = os.path.join(context.volume_path, "lib/apk/db/installed")
        if not os.path.exists(db_path):
            return result

        # Parse APK DB
        # Format:
        # P:package
        # V:version
        # ...
        # o:file_path (owned file)
        
        pkgs = self._parse_apk_db(db_path)
        
        # Populate Packages
        for p in pkgs:
             pkg_meta = PackageMetadata(
                 name=p['name'],
                 version=p['version'],
                 files=[FileMetadata(path=f) for f in p['files']]
             )
             if context.cve_analysis:
                 self._enrich_with_cve(pkg_meta)
             result.packages.append(pkg_meta)

        # Service Analysis
        services_to_process = []
        if context.init_system:
             services_to_process = context.init_system.get_all_services(context.volume_path)
        else:
             # Fallback logic?
             # Alpine usually uses OpenRC. If OpenRC analyzer didn't run, we might verify /etc/init.d manually?
             # But usually context.init_system WILL be set if we detect OpenRC.
             pass

        for svc in services_to_process:
            exec_paths = svc.executables
            if not exec_paths: continue
            
            # Find owner
            # APK `o:` lines give us files.
            # We can use the already parsed `pkgs` list
            
            owner = "unknown"
            version = "unknown"
            
            for p in pkgs:
                found = False
                for f in p['files']:
                     # Check if any exec path matches
                     # exec_paths are absolute /bin/foo
                     # APK files are relative or absolute? Usually relative to root without leading / in older versions, 
                     # but let's check.
                     # "o:bin/busybox"
                     
                     for ep in exec_paths:
                         # Normalize ep
                         ep_normalized = ep.lstrip('/')
                         if f == ep_normalized:
                             owner = p['name']
                             version = p['version']
                             found = True
                             break
                if found: break
            
            svc.associated_package = owner
            svc.version = version
            if not any(s.name == svc.name for s in result.services):
                result.services.append(svc)

        self._print_table(result)
        self._save_output(context, result)
        return result

    def analyze_chroot(self, context: AnalysisContext) -> AnalysisResult:
        # TODO: Implement bootup analysis for Alpine/OpenRC?
        # OpenRC doesn't use systemd-analyze.
        # We might parse /var/log/dmesg or rc.log if available?
        print("Chroot analysis for APK/OpenRC not significantly implemented yet.")
        return self.analyze_static(context)

    def _parse_apk_db(self, db_path: str) -> List[Dict[str, Any]]:
        pkgs = []
        current_pkg = {}
        try:
            with open(db_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        if current_pkg.get('name'):
                            pkgs.append(current_pkg)
                        current_pkg = {}
                        continue
                    
                    if line.startswith('P:'):
                        current_pkg['name'] = line[2:]
                        current_pkg.setdefault('files', [])
                    elif line.startswith('V:'):
                        current_pkg['version'] = line[2:]
                    elif line.startswith('o:'): # Owned file (not directory)
                        # usually "usr/bin/foo"
                        if 'files' not in current_pkg: current_pkg['files'] = []
                        current_pkg['files'].append(line[2:])
                
                if current_pkg.get('name'):
                    pkgs.append(current_pkg)
        except Exception as e:
            print(f"Error parsing APK DB: {e}")
        return pkgs

    def _enrich_with_cve(self, package: PackageMetadata):
        if not check_nvdlib_available():
            return
        analyzer = CVEAnalyzer()
        cves = analyzer.lookup_cves(package.name, package.version)
        package.vulnerabilities = [
            {'cve_id': c.cve_id, 'severity': c.severity, 'score': c.score} 
            for c in cves
        ]

    def _save_output(self, context: AnalysisContext, result: AnalysisResult):
        from ..output.writer import save_analysis_result
        save_analysis_result(context, result)
        
    def _print_table(self, result: AnalysisResult):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Version", style="dim")
        table.add_column("Services")
        table.add_column("CVEs", style="red")
        
        for pkg in result.packages:
            services = [s.name for s in result.services if s.associated_package == pkg.name]
            cve_txt = f"{len(pkg.vulnerabilities)} CVEs" if pkg.vulnerabilities else "None"
            table.add_row(
                pkg.name,
                pkg.version,
                "\n".join(services),
                cve_txt
            )
        print(table)
