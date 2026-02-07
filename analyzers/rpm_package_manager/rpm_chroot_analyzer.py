import os
import re
import rpm
import json
import subprocess
from typing import Dict, List, Union
from rich import print

from ..output_formatting.time_plot import RpmTimeGraphPlot
from ..output_formatting.cdx import convert_to_cdx_rpm_chroot
from ..package_utils.rpm_utils import rpm_utils


class rpm_chroot_analysis:
    def __init__(self, volume_path: str, output_opt: str, graphic_plot: bool):
        self.volume_path = volume_path
        self.output_opt = output_opt
        self.graphic_plot = graphic_plot
        if os.path.exists(f"{self.volume_path}/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "lib/systemd/system")
        elif os.path.exists(f"{self.volume_path}/usr/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "usr/lib/systemd/system")
        else:
            self.systemd_path: str = os.path.join(
                self.volume_path, "etc/systemd/system")
        self.image_path = "SVG//bootup.svg"
        self.packages_json: Dict[str,
                                 List[Dict[str, Union[str, List[str]]]]] = {}
        self.utils = rpm_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path,
        )
        self.rpm_chroot_process()

    def set_rpm_db_path(self):
        rpm_db_path = os.path.join(self.volume_path, 'var', 'lib', 'rpm')
        rpm.addMacro("_dbpath", rpm_db_path)

    def create_packages_json(self) -> None:
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
                    self.packages_json.setdefault(package_name, {
                        'PackageName': package_name,
                        'PackageVersion': package_version,
                        'FilesAssociated': service_files
                    })

    def run_bootup_analysis(self) -> None:
        try:
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/bin", "/bin"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/lib", "/lib"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/lib64", "/lib64"], check=True)
            subprocess.run(["sudo", "mount", "--bind",
                            f"{self.volume_path}/usr", "/usr"], check=True)

            subprocess.run(
                [
                    "sudo",
                    "chroot",
                    self.volume_path,
                    "systemd-analyze",
                    "plot"
                ], check=True, stdout=open("SVG//bootup.svg", "w+")
            )
        except subprocess.CalledProcessError as e:
            print("Error:", e)

    def extract_service_times(self) -> None:
        pattern = re.compile(r'([^<>\n]+\.service) \((\d+ms)\)')
        service_times = {}

        with open(self.image_path, 'r') as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    service_name = match.group(1)
                    time = match.group(2)
                    service_times[service_name] = time

        self.extracted_info = service_times

    def rpm_chroot_process(self) -> None:
        self.run_bootup_analysis()
        self.extract_service_times()
        self.create_packages_json()

        organized_data = {}

        for service_name, time in self.extracted_info.items():
            executable_paths = self.utils.extract_executable(service_name)
            if not executable_paths:
                continue

            for package_name, package_data in self.packages_json.items():
                if 'FilesAssociated' in package_data and isinstance(
                        package_data['FilesAssociated'], list):
                    for file_path in package_data['FilesAssociated']:
                        if service_name in file_path:
                            service_info = {
                                'PackageVersion': package_data[
                                    'PackageVersion'],
                                'Time': str(time),
                                'ExecutablePaths': executable_paths
                            }

                            if package_name not in organized_data:
                                organized_data[package_name] = {
                                    'PackageVersion': package_data[
                                        'PackageVersion'],
                                    'ServiceFiles': {}
                                }

                            organized_data[package_name]['ServiceFiles'][
                                service_name] = service_info

        output_json = {}

        for package_name, package_info in organized_data.items():
            package_data = {
                'PackageVersion': package_info['PackageVersion'],
                'ServiceFiles': []
            }
            for service_name, service_info in package_info[
                    'ServiceFiles'].items():
                service_data = {
                    'ServiceName': service_name,
                    'ExecutionTime': service_info['Time'],
                    'ExecutablePaths': service_info['ExecutablePaths']
                }
                package_data['ServiceFiles'].append(service_data)

            output_json[package_name] = package_data

        self.organized_data = json.dumps(output_json, indent=4)
        cdx_output = convert_to_cdx_rpm_chroot(self.organized_data)
        if self.output_opt:
            try:
                with open(self.output_opt, 'w+') as out_file:
                    json.dump(cdx_output, out_file, indent=4)
            except Exception as e:
                print(f"Error writing to output file: {e}")
        self.utils.display_service_info(self.organized_data)
        if self.graphic_plot is True:
            RpmTimeGraphPlot(
                service_files_path=self.systemd_path,
                json_data=self.organized_data
            )
        else:
            pass
