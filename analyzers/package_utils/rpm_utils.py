import os
import re
import json
from rich import print
from rich.table import Table
from typing import List, Set


class rpm_utils:
    def __init__(
            self,
            systemd_path: str = "",
            volume_path: str = ""
    ) -> None:
        self.systemd_path = systemd_path
        self.volume_path = volume_path
        pass

    def extract_executable(
        self,
        name: str
    ) -> List[str]:
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
                        executable_paths.append(path)
        return executable_paths

    def parse_executable_path(self, command: str) -> str:
        match = re.match(r'^[a-zA-Z0-9_./-]+', command)
        if match:
            return match.group(0)
        return ""

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

    def display_service_info(self, organized_data) -> None:
        data = json.loads(organized_data)
        table = Table(show_header=True, header_style="bold magenta")

        table.add_column("Package", style="cyan")
        table.add_column("Service Name", style="green")
        table.add_column("Executable Paths", style="blue")
        table.add_column("Execution Time", style="yellow")

        for package_name, package_data in data.items():
            for service_info in package_data["ServiceFiles"]:
                table.add_row(
                    package_name,
                    service_info["ServiceName"],
                    "\n".join(service_info["ExecutablePaths"]),
                    service_info["ExecutionTime"]
                )

        print(table)
