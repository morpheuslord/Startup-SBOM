import os
import re
from rich import print
from rich.table import Table
from typing import List, Union, Dict, Optional

from ..output_formatting.apt_outputs import chroot_mode_entry_service
from ..output_formatting.apt_outputs import static_mode_entry_service


class apt_utils:
    def __init__(
            self,
            dpkg_path: str = "",
            systemd_path: str = "",
            info_path: str = "",
            volume_path: str = ""

    ) -> None:
        self.dpkg_status_path = dpkg_path
        self.systemd_path = systemd_path
        self.info_path = info_path
        self.volume_path = volume_path
        pass

    """
    LISTING SERVICE FILES
    """

    def analyze_services(self, list_name: str = None) -> List[str]:
        service_files = []

        try:
            if list_name:
                list_file_path = os.path.join(self.info_path, list_name)
                if os.path.exists(list_file_path):
                    with open(list_file_path, 'r') as file:
                        for line in file:
                            if re.search(r'\.service\b(?![.\w])', line):
                                service_files.append(line.strip())

            else:
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
        try:
            package_versions = {}
            with open(
                    self.dpkg_status_path,
                    'r', encoding='utf-8',
                    errors='ignore'
            ) as status_file:
                current_package = None

                for line in status_file:
                    line = line.strip()

                    if line.startswith('Package:'):
                        current_package = line.split(': ')[1]
                        if not package_name or current_package == package_name:
                            package_versions[current_package] = ''
                    elif line.startswith('Version:') and current_package:
                        if not package_name or current_package == package_name:
                            package_versions[
                                current_package] = line.split(': ')[
                                1]
                    elif line == '' and current_package:
                        current_package = None

            if package_name:
                return package_versions.get(package_name, None)
            else:
                return package_versions

        except FileNotFoundError as e:
            print(f"Error: {self.dpkg_status_path} not found. {e}")
            return {} if not package_name else None
        except Exception as e:
            print(f"Error extracting package version: {e}")
            return {} if not package_name else None

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
                        if os.path.isfile(path):
                            if os.path.islink(path):
                                real_path = os.path.realpath(path)
                            else:
                                real_path = os.path.abspath(path)
                            executable_paths.append(real_path)
            else:
                service_path_mounted = os.path.join(
                    self.volume_path, name_or_service_file)

                if os.path.exists(service_path_mounted):
                    with open(service_path_mounted, 'r') as file:
                        for line in file:
                            match = re.search(
                                r'Exec(?:Start|Stop|Pre)?=(\S+)', line)
                            if match:
                                executable_path = match.group(1)
                                if os.path.islink(executable_path):
                                    real_path = os.path.realpath(
                                        executable_path)
                                else:
                                    real_path = os.path.abspath(
                                        executable_path)
                                executable_paths.append(real_path)

        except Exception as e:
            print(f"Error extracting executable paths: {e}")

        return executable_paths

    """
    LISTING INFO FILES
    """

    def analyze_info(
            self,
            exec_paths: List[str],
            package_versions: Dict[str, str] = None
    ) -> Union[List[str], Dict[str, str]]:
        try:
            info_files = []

            if os.path.exists(self.info_path):
                for file_name in os.listdir(self.info_path):
                    if file_name.endswith(".list"):
                        list_file_path = os.path.join(
                            self.info_path, file_name)
                        with open(list_file_path, 'r') as list_file:
                            content = list_file.read()

                            for exec_path in exec_paths:
                                real_path = os.path.realpath(
                                    exec_path) if os.path.islink(
                                    exec_path) else os.path.abspath(exec_path)
                                if real_path in content:
                                    info_files.append(
                                        os.path.splitext(file_name)[0])
                                    break

            if package_versions is not None:
                info_files_with_versions = {}
                for file_name in info_files:
                    package_name = os.path.splitext(file_name)[0]
                    if package_name in package_versions:
                        info_files_with_versions[
                            package_name] = package_versions[package_name]
                return info_files_with_versions
            else:
                return info_files

        except Exception as e:
            print(f"Error analyzing info files: {e}")
            return [] if package_versions is None else {}

    def list_info_files(self) -> List[str]:
        try:
            files_with_list_extension = []

            # Check if info_path exists and gather .list files
            if os.path.exists(self.info_path):
                for filename in os.listdir(self.info_path):
                    if filename.endswith(".list"):
                        files_with_list_extension.append(filename)

            return files_with_list_extension

        except Exception as e:
            print(f"Error listing info files: {e}")
            return []

    """
    GENERATE TABLE OUTPUTS
    """

    # CHROOT ANALYSIS
    def generate_table_chroot(
            self, entries: List[chroot_mode_entry_service]) -> None:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Version", style="dim")
        table.add_column("Service Name")
        table.add_column("Executable Path")
        table.add_column("Executable Names")
        table.add_column("Execution Time")

        for entry in entries:
            package_name = entry.Package if entry.Package else ""
            service_name = entry.ServiceName
            version = entry.Version
            executable_paths = "\n".join(entry.ExecutablePath)
            executable_names = "\n".join(entry.ExecutableNames)
            execution_time = [str(entry.ExecutionTime)]
            execution_time_str = "\n".join(execution_time)
            table.add_row(package_name, version, service_name,
                          executable_paths,
                          executable_names, execution_time_str)

        print(table)

    # STATIC INFO ANALYSIS
    def generate_table_static_info(self, packages) -> None:
        try:
            if not packages:
                print("No entries to display.")
                return

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Package", style="dim")
            table.add_column("Version", style="dim")
            table.add_column("Service Name")
            table.add_column("Executable Path")
            table.add_column("Executable Names")

            for package_name, entry in packages.items():
                table.add_row(
                    entry.Package,
                    entry.Version,
                    entry.ServiceName,
                    "\n".join(entry.ExecutablePath),
                    "\n".join(entry.ExecutableName)
                )

            print(table)

        except Exception as e:
            print(f"Error generating output: {e}")

    # STATIC SERVICE ANALYSIS
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

            for entry in entries:
                table.add_row(
                    entry.Package,
                    entry.Version,
                    entry.ServiceName,
                    "\n".join(entry.ExecutablePath),
                    "\n".join(entry.ExecutableNames)
                )

            print(table)
        except Exception as e:
            print(f"Error generating table: {e}")
