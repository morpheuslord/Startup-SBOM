import os
import re
from rich import print
from rich.table import Table
from typing import List, Union, Dict, Optional

from ..output_formatting.pacman_outputs import chroot_mode_entry_service
from ..output_formatting.pacman_outputs import static_mode_entry_service


class pacman_utils:
    def __init__(
            self,
            systemd_path: str = "",
            volume_path: str = ""
    ) -> None:
        self.systemd_path = systemd_path
        self.volume_path = volume_path
        self.local_db_path = os.path.join(self.volume_path, 'var/lib/pacman/local')

    """
    LISTING SERVICE FILES
    """

    def analyze_services(self) -> List[str]:
        service_files = []
        try:
            if os.path.exists(self.systemd_path):
                service_files.extend([
                    file for file in os.listdir(self.systemd_path)
                    if file.endswith(".service")
                ])
        except OSError as e:
            print(f"Error analyzing service files: {e}")

        return service_files

    """
    EXTRACT PACKAGE VERSIONS
    """

    def extract_version(
            self,
            package_name: Optional[str] = None
    ) -> Union[str, Dict[str, str]]:
        package_versions = {}
        try:
            if not os.path.exists(self.local_db_path):
                return {}

            # Iterate over directories in /var/lib/pacman/local/
            # Directory name format: package-version-release
            # We can also read 'desc' file for precise version
            for entry in os.listdir(self.local_db_path):
                entry_path = os.path.join(self.local_db_path, entry)
                if not os.path.isdir(entry_path):
                    continue
                
                desc_file = os.path.join(entry_path, 'desc')
                if os.path.exists(desc_file):
                   name, version = self._parse_desc_file(desc_file)
                   if name and version:
                       if package_name:
                           if name == package_name:
                               return version
                       else:
                           package_versions[name] = version

            if package_name:
                return package_versions.get(package_name, None)
            else:
                return package_versions

        except Exception as e:
            print(f"Error extracting package version: {e}")
            return {} if not package_name else None

    def _parse_desc_file(self, filepath: str):
        """Parse pacman desc file to get name and version."""
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

    """
    EXTRACT EXECUTABLE PATHS
    """

    def extract_executable_paths(self, name_or_service_file: str) -> List[str]:
        executable_paths = []
        try:
            service_file_path = os.path.join(
                self.systemd_path, name_or_service_file)

            if os.path.exists(service_file_path):
                with open(service_file_path, 'r') as file:
                    content = file.read()
                    matches = re.findall(
                        r'(Exec(?:Start|Stop|Pre)?=)(.+)', content)
                    for match in matches:
                        args = match[1].split()
                        path = args[0].strip()
                        # Handle paths starting with - (ignore return code)
                        if path.startswith('-'):
                            path = path[1:]
                            
                        if os.path.isfile(path):
                            if os.path.islink(path):
                                real_path = os.path.realpath(path)
                            else:
                                real_path = os.path.abspath(path)
                            executable_paths.append(real_path)
                        elif path.startswith('/'):
                             # Even if file doesn't exist (e.g. in static analysis of mounted volume), keep the path
                             # But we should try to resolve it relative to volume_path
                             full_path = os.path.join(self.volume_path, path.lstrip('/'))
                             if os.path.exists(full_path):
                                 executable_paths.append(path) # Keep original path for matching
                             else:
                                 # Still keep it as candidate
                                 executable_paths.append(path)
            
        except Exception as e:
            print(f"Error extracting executable paths: {e}")

        return executable_paths

    """
    LISTING INFO FILES (MAPPING FILES TO PACKAGES)
    """

    def analyze_info(
            self,
            exec_paths: List[str],
            package_versions: Dict[str, str] = None
    ) -> Union[List[str], Dict[str, str]]:
        info_files = [] # List of package names
        try:
            if not os.path.exists(self.local_db_path):
                return []

            for pk_dir in os.listdir(self.local_db_path):
                 entry_path = os.path.join(self.local_db_path, pk_dir)
                 if not os.path.isdir(entry_path):
                     continue
                 
                 files_file = os.path.join(entry_path, 'files')
                 if not os.path.exists(files_file):
                     continue
                     
                 with open(files_file, 'r', encoding='utf-8', errors='ignore') as f:
                     content = f.read()
                     # Pacman files list usually doesn't have leading /
                     # content is list of files
                     
                     matched = False
                     for exec_path in exec_paths:
                         # Strip leading slash to match pacman format
                         rel_path = exec_path.lstrip('/')
                         
                         # Simple check: is the path in the file?
                         # To be more robust we could split lines
                         if rel_path in content.splitlines():
                             # Get package name from desc or dir name
                             # We can use _parse_desc_file to be sure
                             desc_file = os.path.join(entry_path, 'desc')
                             name, _ = self._parse_desc_file(desc_file)
                             if name:
                                 info_files.append(name)
                                 matched = True
                                 break
                     if matched:
                         # If we found an owner for one execution path, does that mean 
                         # we stop checking this package for other paths? 
                         # Or we stop checking other packages for this path?
                         # The loop structure in apt_utils was:
                         # for file_name in os.listdir...
                         #   for exec_path in exec_paths...
                         #     if found -> append and break (inner loop)
                         pass

            # Remove duplicates
            info_files = list(set(info_files))

            if package_versions is not None:
                info_files_with_versions = {}
                for package_name in info_files:
                    if package_name in package_versions:
                        info_files_with_versions[package_name] = package_versions[package_name]
                return info_files_with_versions
            else:
                return info_files

        except Exception as e:
            print(f"Error analyzing info files: {e}")
            return [] if package_versions is None else {}

    """
    GENERATE TABLE OUTPUTS
    """

    def generate_table_chroot(
            self, entries: List[chroot_mode_entry_service]) -> None:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Version", style="dim")
        table.add_column("Service Name")
        table.add_column("Executable Path")
        table.add_column("Executable Names")
        table.add_column("Execution Time")
        table.add_column("CVEs", style="red")

        for entry in entries:
            package_name = entry.Package if entry.Package else ""
            service_name = entry.ServiceName
            version = entry.Version
            executable_paths = "\n".join(entry.ExecutablePath)
            executable_names = "\n".join(entry.ExecutableNames)
            execution_time = [str(entry.ExecutionTime)]
            execution_time_str = "\n".join(execution_time)
            
            vuln_info = self._format_vulnerability_info(
                getattr(entry, 'Vulnerabilities', [])
            )
            
            table.add_row(package_name, version, service_name,
                          executable_paths,
                          executable_names, execution_time_str, vuln_info)

        print(table)

    def generate_table_static_service(
            self, entries: List[static_mode_entry_service]) -> None:
        try:
            if not entries:
                print("No entries to display.")
                return

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Package", style="dim")
            table.add_column("Version", style="dim")
            table.add_column("Service Name")
            table.add_column("Executable Path")
            table.add_column("Executable Names")
            table.add_column("CVEs", style="red")

            for entry in entries:
                vuln_info = self._format_vulnerability_info(
                    getattr(entry, 'Vulnerabilities', [])
                )
                
                table.add_row(
                    entry.Package,
                    entry.Version,
                    entry.ServiceName,
                    "\n".join(entry.ExecutablePath),
                    "\n".join(entry.ExecutableNames),
                    vuln_info
                )

            print(table)
        except Exception as e:
            print(f"Error generating table: {e}")

    def _format_vulnerability_info(self, vulnerabilities: list) -> str:
        """Format vulnerability information for table display."""
        if not vulnerabilities:
            return "[green]None[/green]"
        
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'LOW')
        
        parts = []
        if critical:
            parts.append(f"[red bold]{critical} CRIT[/red bold]")
        if high:
            parts.append(f"[red]{high} HIGH[/red]")
        if medium:
            parts.append(f"[yellow]{medium} MED[/yellow]")
        if low:
            parts.append(f"[blue]{low} LOW[/blue]")
        
        return "\n".join(parts) if parts else f"{len(vulnerabilities)} CVEs"
