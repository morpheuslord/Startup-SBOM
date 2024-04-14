import os
import re
import json
import subprocess
from rich import print
from typing import Dict

from ..output_formatting.apt_outputs import chroot_mode_entry_service
from ..output_formatting.time_plot import AptTimeGraphPlot
from ..package_utils.apt_utils import apt_utils


class apt_chroot_analysis:
    def __init__(
            self,
            volume_path: str, output_opt: str, graphic_plot: bool) -> None:
        self.volume_path: str = volume_path
        self.info_path: str = f"{self.volume_path}/var/lib/dpkg/info"
        self.dpkg_status_path: str = f"{self.volume_path}/var/lib/dpkg/status"
        self.output_opt: str = output_opt
        self.graphic_plot: bool = graphic_plot
        self.extracted_info: Dict[str, str] = {}
        if os.path.exists(f"{self.volume_path}/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "lib/systemd/system")
        elif os.path.exists(f"{self.volume_path}/usr/lib/systemd/system"):
            self.systemd_path: str = os.path.join(
                self.volume_path, "usr/lib/systemd/system")
        else:
            self.systemd_path: str = os.path.join(
                self.volume_path, "etc/systemd/system")
        self.out_data: str = ""
        self.run_bootup_analysis()
        self.extract_service_times()
        self.service_analysis_process()

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
            self.image_path = "SVG//bootup.svg"
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

    def service_analysis_process(self) -> None:
        entries = []
        utils = apt_utils(
            systemd_path=self.systemd_path,
            dpkg_path=self.dpkg_status_path,
            volume_path=self.volume_path,
            info_path=self.info_path
        )
        for service_name, time in self.extracted_info.items():
            executable_paths = utils.extract_executable_paths(
                service_name)
            if not executable_paths:
                continue
            info_files = utils.analyze_info(
                exec_paths=executable_paths)
            exec_names = [os.path.basename(path) for path in executable_paths]
            for package_name in info_files:
                version = utils.extract_version(
                    package_name=package_name)

                entry = chroot_mode_entry_service(
                    Package=package_name,
                    ServiceName=service_name,
                    ExecutablePath=executable_paths,
                    ExecutableNames=exec_names,
                    ExecutionTime=str(time),
                    Version=version
                )
                entries.append(entry)

        combined_entries = chroot_mode_entry_service.combine_entries(entries)

        self.out_data = json.dumps([entry.dict()
                                   for entry in combined_entries], indent=4)

        if self.output_opt:
            try:
                with open(self.output_opt, 'w+') as out_file:
                    out_file.write(self.out_data)
            except Exception as e:
                print(f"Error writing to output file: {e}")
        utils.generate_table_chroot(entries=combined_entries)

        if self.graphic_plot:
            try:
                AptTimeGraphPlot(
                    service_files_path=self.systemd_path,
                    json_data=self.out_data
                )
            except Exception as e:
                print(f"Error plotting graph: {e}")
