import os
import re
import json
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich import print

from ..output_formats.apt_outputs import static_mode_entry_info
from ..output_formats.apt_outputs import static_mode_entry_service


class static_analysis_info_files:
    def __init__(self, volume_path: str, output_opt: str) -> None:
        try:
            self.volume_path: str = volume_path
            self.info_path: str = f"{self.volume_path}/var/lib/dpkg/info"
            self.output_opt: str = output_opt
            self.entries: List[static_mode_entry_info] = []
            self.packages: Dict[str, static_mode_entry_info] = {}
            self.static_analysis_fast_process()
        except Exception as e:
            print(f"Error in initialization: {e}")

    def list_info_files(self) -> List[str]:
        try:
            files_with_list_extension = []
            for filename in os.listdir(self.info_path):
                if filename.endswith(".list"):
                    files_with_list_extension.append(filename)
            return files_with_list_extension
        except Exception as e:
            print(f"Error listing info files: {e}")
            return []

    def list_service_files(self, list_name: str) -> List[str]:
        try:
            file_paths = []
            list_file_path = os.path.join(self.info_path, list_name)
            if os.path.exists(list_file_path):
                with open(list_file_path, 'r') as file:
                    for line in file:
                        if re.search(r'\.service\b(?![.\w])', line):
                            file_paths.append(line.strip())
            return file_paths
        except Exception as e:
            print(f"Error listing service files: {e}")
            return []

    def list_executable_paths(self, service_path: str) -> List[str]:
        try:
            service_path_mounted = f"{self.volume_path}/{service_path}"
            executable_paths = []
            if os.path.exists(service_path_mounted):
                with open(service_path_mounted, 'r') as file:
                    for line in file:
                        match = re.search(
                            r'Exec(?:Start|Stop|Pre)?=(\S+)', line)
                        if match:
                            executable_path = match.group(1)
                            if os.path.islink(executable_path):
                                real_path = os.path.realpath(executable_path)
                            else:
                                real_path = os.path.abspath(executable_path)
                            executable_paths.append(real_path)
            return executable_paths
        except Exception as e:
            print(f"Error listing executable paths: {e}")
            return []

    def extract_version(self, package_name: str) -> str:
        try:
            dpkg_status_path = f"{self.volume_path}/var/lib/dpkg/status"
            with open(dpkg_status_path, 'r') as status_file:
                current_package = None
                current_version = None

                for line in status_file:
                    line = line.strip()

                    if line.startswith("Package: "):
                        current_package = line.split("Package: ")[1].strip()
                        if current_package == package_name:
                            return current_version

                    elif line.startswith("Version: "):
                        current_version = line.split("Version: ")[1].strip()

                return None
        except Exception as e:
            print(f"Error extracting package version: {e}")
            return None

    def static_analysis_fast_process(self):
        try:
            list_files = self.list_info_files()

            for list_name in list_files:
                package_name = os.path.splitext(list_name)[0]
                version = self.extract_version(package_name)

                service_files = self.list_service_files(list_name)

                for service_name in service_files:
                    executable_paths = self.list_executable_paths(service_name)
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

            self.generate_output()
            self.save_packages_to_json()
        except Exception as e:
            print(f"Error in fast process: {e}")

    def save_packages_to_json(self) -> None:
        try:
            serializable_packages = [
                entry.custom_output() for entry in self.packages.values()
            ]
            with open(self.output_opt, 'w') as f:
                json.dump(serializable_packages, f, indent=4)
            print(f"Successfully saved packages to {self.output_opt}")
        except Exception as e:
            print(f"Error saving packages to JSON: {e}")

    def generate_output(self) -> None:
        try:
            if not self.packages:
                print("No entries to display.")
                return

            console = Console()
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Package", style="dim")
            table.add_column("Version", style="dim")
            table.add_column("Service Name")
            table.add_column("Executable Path")
            table.add_column("Executable Names")

            for package_name, entry in self.packages.items():
                table.add_row(
                    entry.Package,
                    entry.Version,
                    entry.ServiceName,
                    "\n".join(entry.ExecutablePath),
                    "\n".join(entry.ExecutableName)
                )

            console.print(table)

        except Exception as e:
            print(f"Error generating output: {e}")


class static_analysis_service_files:
    def __init__(self, volume_path: str, output_opt: str) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
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
        self.service_analysis_process()

    def get_systemd_path(self) -> str:
        paths = [
            os.path.join(self.volume_path, "lib/systemd/system"),
            os.path.join(self.volume_path, "usr/lib/systemd/system"),
            os.path.join(self.volume_path, "etc/systemd/system")
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return ""

    def read_service_files(self) -> List[str]:
        try:
            service_files = []
            if os.path.exists(self.systemd_path):
                service_files.extend([
                    file for file in os.listdir(self.systemd_path)
                    if file.endswith(".service")
                ])
            return service_files
        except OSError as e:
            print(f"Error reading service files: {e}")
            return []

    def extract_executable(self, service_file: str) -> List[str]:
        try:
            executable_paths = []
            service_file_path = os.path.join(self.systemd_path, service_file)

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
            return executable_paths
        except OSError as e:
            print(f"Error extracting executable paths: {e}")
            return []

    def service_analysis_process(self):
        try:
            self.status_file_path = f'{self.volume_path}/var/lib/dpkg/status'
            service_files = self.read_service_files()
            entries = []

            package_versions = self.get_package_versions()

            for service_file in service_files:
                executable_paths = self.extract_executable(service_file)
                if not executable_paths:
                    continue

                info_files = self.check_info_files(
                    executable_paths, package_versions)
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
            self.generate_output(combined_entries)

        except Exception as e:
            print(f"Service Process Error: {e}")

    def get_package_versions(self) -> dict:
        package_versions = {}
        try:
            with open(
                    self.status_file_path,
                    'r', encoding='utf-8', errors='ignore') as status_file:
                current_package = None
                for line in status_file:
                    line = line.strip()
                    if line.startswith('Package:'):
                        current_package = line.split(': ')[1]
                        package_versions[current_package] = ''
                    elif line.startswith('Version:') and current_package:
                        package_versions[current_package] = line.split(': ')[1]
                    elif line == '' and current_package:
                        current_package = None
        except FileNotFoundError:
            print(f"Error: {self.status_file_path} not found.")
        return package_versions

    def check_info_files(
            self, exec_paths: List[str], package_versions: dict) -> dict:
        info_files = {}
        try:
            if os.path.exists(self.info_path):
                for file_name in os.listdir(self.info_path):
                    if file_name.endswith(".list"):
                        list_file_path = os.path.join(
                            self.info_path, file_name)
                        with open(list_file_path, 'r') as list_file:
                            content = list_file.read()
                            package_name = os.path.splitext(file_name)[0]
                            if package_name in package_versions:
                                for exec_path in exec_paths:
                                    if exec_path in content:
                                        info_files[
                                            package_name] = package_versions[
                                                package_name]
                                        break
        except OSError as e:
            print(f"Error checking info files: {e}")
        return info_files

    def generate_output(
            self, entries: List[static_mode_entry_service]) -> None:
        try:
            if not entries:
                print("No entries to display.")
                return

            if self.output_opt == '':
                self.generate_table(entries)
            else:
                with open(self.output_opt, 'w+') as outfile:
                    out_entry = []
                    for entry in entries:
                        if entry.Package:
                            entry_json = entry.json()
                            out_entry.append(entry_json)
                    outfile.write(json.dumps(out_entry))

                print(f"Output written to {self.output_opt}")
                # Display table in console
                self.generate_table(entries)

        except Exception as e:
            print(f"Error generating output: {e}")

    def generate_table(self, entries: List[static_mode_entry_service]) -> None:
        try:
            if not entries:
                print("No entries to display.")
                return

            console = Console()
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

            console.print(table)
        except Exception as e:
            print(f"Error generating table: {e}")


class apt_static_analysis:

    def __init__(
            self, volume_path: str, process_opt: str, output: str) -> None:
        self.volume_path: str = volume_path
        self.process_opt: str = process_opt
        self.output: str = output
        self.main_process()

    def main_process(self):
        try:
            if self.process_opt == "info":
                static_analysis_info_files(
                    volume_path=self.volume_path, output_opt=self.output
                )
            elif self.process_opt == "service":
                static_analysis_service_files(
                    volume_path=self.volume_path, output_opt=self.output
                )
            else:
                print("Invalid process option. Choose 'info' or 'service'.")
        except Exception as e:
            print(f"An error occurred during the main process: {e}")
