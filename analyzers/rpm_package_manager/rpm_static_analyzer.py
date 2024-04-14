import os
import rpm
import json
from typing import Dict
from rich.table import Table
from rich.console import Console

from ..output_formatting.rpm_outputs import PackageServiceInfo
from ..output_formatting.rpm_outputs import CustomJSONEncoder
from ..output_formatting.rpm_outputs import ServiceInfo
from ..package_utils.rpm_utils import rpm_utils


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
        self.utils = rpm_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path,
        )
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
                    service_info = ServiceInfo(executable_paths=set())
                    for service_file in service_files:
                        executable_paths = self.utils.extract_executable_paths(
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

    def service_analysis_process(self) -> None:
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Package", style="cyan")
        table.add_column("Package Version", style="green")
        table.add_column("Service Name", style="blue")
        table.add_column("Executable Paths", style="yellow")

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
