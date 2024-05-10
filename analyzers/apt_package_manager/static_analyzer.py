import os
import json
from typing import List, Dict
from rich import print

from ..output_formatting.apt_outputs import static_mode_entry_info
from ..output_formatting.apt_outputs import static_mode_entry_service
from ..output_formatting.cdx import convert_to_cdx_apt_static_info
from ..output_formatting.cdx import convert_to_cdx_apt_static_service
from ..package_utils.apt_utils import apt_utils


class static_analysis_info_files:
    def __init__(self, volume_path: str, output_opt: str) -> None:
        try:
            self.volume_path: str = volume_path
            self.info_path: str = f"{self.volume_path}/var/lib/dpkg/info"
            self.output_opt: str = output_opt
            self.entries: List[static_mode_entry_info] = []
            self.packages: Dict[str, static_mode_entry_info] = {}
            self.utils = apt_utils(
                volume_path=self.volume_path,
                info_path=self.info_path,
                dpkg_path=f'{self.volume_path}/var/lib/dpkg/status'
            )
            self.static_analysis_fast_process()
        except Exception as e:
            print(f"Error in initialization: {e}")

    def static_analysis_fast_process(self):
        try:
            list_files = self.utils.list_info_files()
            for list_name in list_files:
                package_name = os.path.splitext(list_name)[0]
                version = self.utils.extract_version(package_name)
                service_files = self.utils.analyze_services(list_name)

                for service_name in service_files:
                    executable_paths = self.utils.extract_executable_paths(
                        service_name)
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

            self.utils.generate_table_static_info(packages=self.packages)
            self.save_packages_to_json()
        except Exception as e:
            print(f"Error in fast process: {e}")

    def save_packages_to_json(self) -> None:
        try:
            serializable_packages = [
                entry.custom_output() for entry in self.packages.values()
            ]
            cdx_out = convert_to_cdx_apt_static_info(serializable_packages)
            with open(self.output_opt, 'w') as f:
                json.dump(cdx_out, f, indent=4)
            print(f"Successfully saved packages to {self.output_opt}")
        except Exception as e:
            if self.output_opt == '':
                pass
            else:
                print(f"Error saving packages to JSON: {e}")


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
        self.status_file_path = f'{self.volume_path}/var/lib/dpkg/status'
        self.utils = apt_utils(
            systemd_path=self.systemd_path,
            volume_path=self.volume_path,
            info_path=self.info_path,
            dpkg_path=self.status_file_path
        )
        self.service_analysis_process()

    def service_analysis_process(self):
        try:
            service_files = self.utils.analyze_services()
            entries = []

            package_versions = self.utils.extract_version()

            for service_file in service_files:
                executable_paths = self.utils.extract_executable_paths(
                    service_file)
                if not executable_paths:
                    continue

                info_files = self.utils.analyze_info(
                    exec_paths=executable_paths,
                    package_versions=package_versions
                )
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

    def generate_output(
            self, entries: List[static_mode_entry_service]) -> None:
        try:
            if not entries:
                print("No entries to display.")
                return

            if self.output_opt == '':
                self.utils.generate_table_static_service(entries)
            else:
                with open(self.output_opt, 'w+') as outfile:
                    out_entry = []
                    for entry in entries:
                        if entry.Package:
                            entry_json = entry.json()
                            out_entry.append(entry_json)
                    cdx_output = convert_to_cdx_apt_static_service(out_entry)
                    outfile.write(json.dumps(cdx_output))

                print(f"Output written to {self.output_opt}")
                self.utils.generate_table_static_service(entries)

        except Exception as e:
            print(f"Error generating output: {e}")


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
