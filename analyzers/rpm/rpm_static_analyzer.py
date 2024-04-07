import os
import re
import rpm
import json
from typing import Dict, Set
from pydantic import BaseModel
from rich.table import Table
from rich.console import Console


class ServiceInfo(BaseModel):
    executable_paths: Set[str]


class PackageServiceInfo(BaseModel):
    package_version: str
    service_names: Dict[str, ServiceInfo]


class PackageInfo(BaseModel):
    root: Dict[str, PackageServiceInfo]


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, 'dict'):
            return obj.dict()
        return super().default(obj)


class rpm_static_analysis:

    def __init__(self, volume_path: str, output_opt: str) -> None:
        self.volume_path: str = volume_path
        self.output_opt: str = output_opt
        self.systemd_path: str = self.get_systemd_path()
        self.set_rpm_db_path()
        self.package_info = self.create_packages_json()
        self.service_analysis_process()

    def get_systemd_path(self) -> str:
        for path in [
                os.path.join(
                    self.volume_path, p) for p in [
                        "lib/systemd/system",
                        "usr/lib/systemd/system",
                        "etc/systemd/system"]]:
            if os.path.exists(path):
                return path
        raise RuntimeError("Systemd path not found in chroot")

    def set_rpm_db_path(self) -> None:
        rpm_db_path = os.path.join(self.volume_path, 'var', 'lib', 'rpm')
        rpm.addMacro("_dbpath", rpm_db_path)

    def create_packages_json(self) -> Dict[str, PackageServiceInfo]:
        package_info = {}

        ts = rpm.TransactionSet()
        mi = ts.dbMatch()

        for hdr in mi:
            package_name = hdr[rpm.RPMTAG_NAME].decode('utf-8')
            package_version = hdr[rpm.RPMTAG_VERSION].decode('utf-8')
            files = hdr[rpm.RPMTAG_FILENAMES]

            if files:
                service_files = [
                    f.decode('utf-8') for f in files if f.decode(
                        'utf-8').endswith('.service')
                ]

                if service_files:
                    # Use set to ensure uniqueness
                    service_info = ServiceInfo(executable_paths=set())
                    for service_file in service_files:
                        executable_paths = self.extract_executable_paths(
                            os.path.join(self.systemd_path, service_file))
                        if executable_paths:
                            service_info.executable_paths.update(
                                executable_paths)

                    if package_name not in package_info:
                        package_info[package_name] = PackageServiceInfo(
                            package_version=package_version, service_names={})
                    package_info[package_name].service_names[
                        service_file] = service_info

        return package_info

    def extract_executable_paths(self, service_file_path: str) -> Set[str]:
        executable_paths = set()

        try:
            with open(service_file_path, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    line = line.strip()
                    if line.startswith(
                            "Exec=") or line.startswith(
                                "ExecStart=") or line.startswith(
                                    "ExecStop=") or line.startswith(
                                        "ExecPre="):
                        command = line.split("=", 1)[1].strip()
                        executable_path = self.parse_executable_path(command)
                        if executable_path:
                            executable_paths.add(executable_path)
        except Exception as e:
            print(f"Error: {e}")

        return executable_paths

    def parse_executable_path(self, command: str) -> str:
        match = re.match(r'^[a-zA-Z0-9_./-]+', command)
        if match:
            return match.group(0)
        return ""

    def service_analysis_process(self) -> None:
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="dim")
        table.add_column("Package Version")
        table.add_column("Service Name")
        table.add_column("Executable Paths")

        for package_name, page_s_i in self.package_info.items():
            package_version = page_s_i.package_version
            for service_name, service_info in page_s_i.service_names.items():
                executable_paths = service_info.executable_paths
                if executable_paths:
                    table.add_row(package_name, package_version,
                                  service_name, ", ".join(executable_paths))
        console.print(table)
        if self.output_opt:
            try:
                with open(self.output_opt, 'w') as json_file:
                    json.dump(self.package_info, json_file,
                              indent=4, cls=CustomJSONEncoder)
                print(f"Scan data saved to: {self.output_opt}")
            except Exception as e:
                print(f"Error saving scan data to JSON file: {e}")
