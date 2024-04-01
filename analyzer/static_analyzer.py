import os
import re
import json
from typing import List
from rich.console import Console
from rich.table import Table

from .output_formats import static_mode_entry_info
from .output_formats import static_mode_entry_service


class static_analysis_info_files:
    def __init__(
        self,
        volume_path: str,
        output: str
    ) -> None:
        try:
            self.volume_path: str = volume_path
            self.info_path: str = f"{self.volume_path}/var/lib/dpkg/info"
            self.output_opt: str = output
            self.static_analysis_fast_process()
        except Exception as e:
            print(f"Error in initialization: {e}")

    def list_info_files(self) -> list[str]:
        try:
            files_with_list_extension = []
            for filename in os.listdir(self.info_path):
                if filename.endswith(".list"):
                    files_with_list_extension.append(
                        os.path.join(filename))
            return files_with_list_extension
        except Exception as e:
            print(f"Error listing info files: {e}")
            return []

    def list_service_files(
        self,
        list_name: str
    ) -> List[str]:
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

    def list_executable_paths(
        self,
        service_path: str
    ) -> List[str]:
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

    def Static_Fast_Table(self):
        try:
            console = Console()
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Package", style="dim")
            table.add_column("Service Name")
            table.add_column("Executable Path")
            table.add_column("Executable Names")
            for entry in self.outputs:
                package = entry["Package"]
                for service_name, info in entry["ServiceInformation"].items():
                    executable_paths = ", ".join(info["ExecutablePath"])
                    exec_names = ", ".join(info["ExecutableName"])
                    table.add_row(package, service_name,
                                  executable_paths, exec_names)
            console.print(table)
        except Exception as e:
            print(f"Error generating static table: {e}")

    def static_analysis_fast_process(self):
        try:
            list_files = self.list_info_files()
            entries = []
            outputs = []
            for names in list_files:
                package_name = re.sub(
                    r'\.list$', '', names)
                service_list = self.list_service_files(names)
                if not service_list:
                    service_list = ["No Service File"]
                else:
                    for services in service_list:
                        executable_info = self.list_executable_paths(services)
                        exec_names = []
                        for execs in executable_info:
                            exec_names.append(os.path.basename(execs))
                        output = static_mode_entry_info(
                            Package=package_name,
                            ServiceName=services,
                            ExecutablePath=executable_info,
                            ExecutableName=exec_names
                        )
                        exec_names = []
                    entries.append(output)
            outputs = [entry.json() for entry in entries]
            self.outputs = outputs
            if self.output_opt == "":
                pass
            else:
                with open(self.output_opt, 'w+') as out:
                    out.write(json.dumps(outputs, indent=4))
            self.Static_Fast_Table()
        except Exception as e:
            print(f"Error in fast process: {e}")


class static_analysis_service_files:

    def __init__(
        self,
        volume_path: str,
        output_opt: str
    ) -> None:
        self.volume_path: str = volume_path
        self.info_path: str = os.path.join(
            self.volume_path, "var/lib/dpkg/info")
        self.systemd_path: str = os.path.join(
            self.volume_path, "lib/systemd/system")
        self.output_opt: str = output_opt
        self.service_analysis_process()

    def read_service_file(self) -> List[str]:
        try:
            service_files = []
            if os.path.exists(self.systemd_path):
                for file in os.listdir(self.systemd_path):
                    if file.endswith(".service"):
                        service_files.append(file)
            return service_files
        except OSError as e:
            print(f"Error reading service files: {e}")
            return []

    def extract_executable(
        self,
        name: str
    ) -> List[str]:
        try:
            executable_paths = []
            service_file_path = os.path.join(self.systemd_path, name)

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

    def check_info_files(
        self,
        exec_paths: List[str]
    ) -> List[str]:
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
                                if exec_path in content:
                                    info_files.append(
                                        os.path.splitext(file_name)[0])
                                    break
            return info_files
        except OSError as e:
            print(f"Error checking info files: {e}")
            return []

    def service_analysis_process(self):
        try:
            service_files = self.read_service_file()
            entries = []

            for service_file in service_files:
                executable_paths_set = set()
                executable_paths = self.extract_executable(service_file)
                executable_paths_set.update(executable_paths)
                info_files = self.check_info_files(executable_paths_set)
                exec_names_set = set()
                for path in executable_paths_set:
                    exec_names_set.add(os.path.basename(path))
                exec_names = list(exec_names_set)
                for package_name in info_files:
                    entry = static_mode_entry_service(
                        Package=package_name,
                        ServiceName=service_file,
                        ExecutablePath=list(executable_paths_set),
                        ExecutableNames=exec_names
                    )
                    entries.append(entry)

            combined_entries = static_mode_entry_service.combine_entries(
                entries)
            if self.output_opt:
                data = json.dumps([entry.dict()
                                  for entry in combined_entries], indent=4)
                with open(self.output_opt, 'w+') as out:
                    out.write(data)
            self.generate_table(combined_entries)
        except Exception as e:
            print(f"Error in service analysis process: {e}")

    def generate_table(
        self,
        entries: List[static_mode_entry_service]
    ) -> None:
        try:
            console = Console()
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Package", style="dim")
            table.add_column("Service Name")
            table.add_column("Executable Path")
            table.add_column("Executable Names")

            for entry in entries:
                package_name = entry.Package if entry.Package else ""
                service_name = entry.ServiceName
                executable_paths = "\n".join(entry.ExecutablePath)
                executable_names = "\n".join(entry.ExecutableNames)
                table.add_row(package_name, service_name,
                              executable_paths, executable_names)

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
                    volume_path=self.volume_path, output=self.output
                )
            elif self.process_opt == "service":
                static_analysis_service_files(
                    volume_path=self.volume_path, output_opt=self.output
                )
            else:
                print("Invalid process option. Choose 'info' or 'service'.")
        except Exception as e:
            print(f"An error occurred during the main process: {e}")
