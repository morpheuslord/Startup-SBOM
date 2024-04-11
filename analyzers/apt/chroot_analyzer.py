import os
import re
import json
import graphviz
import subprocess
from rich import print
from rich.table import Table
from rich.console import Console
from typing import Dict, List, Any

from .output_formats import chroot_mode_entry_service


class TimeGraphPlot:
    def __init__(
            self, service_files_path: str, json_data: Dict[str, Any]) -> None:
        self.service_files_path = service_files_path
        self.json_data = json_data
        self.service_data = self.parse_service_data()
        if self.service_data:
            self.generate_flowchart()

    def parse_service_data(self) -> Dict[str, Any]:
        service_data = {}
        try:
            json_data = json.loads(self.json_data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON data: {e}")
            return service_data

        for package_data in json_data:
            package_name = package_data.get("Package")
            service_names = package_data.get("ExecutableNames", [])
            execution_time = package_data.get('ExecutionTime')

            if not execution_time:
                print(f"ExecutionTime not found for {package_name}")
                continue

            exec_time = int(''.join(filter(str.isdigit, str(execution_time))))

            package_services = {}
            for service_name in service_names:
                service_file_path = os.path.join(
                    self.service_files_path, f"{service_name}.service")
                if os.path.exists(service_file_path):
                    with open(service_file_path, 'r') as f:
                        lines = f.readlines()
                        before = []
                        after = []
                        for line in lines:
                            if line.startswith("Before="):
                                before.extend(
                                    line.strip().split('=')[1].split())
                            elif line.startswith("After="):
                                after.extend(
                                    line.strip().split('=')[1].split())
                        package_services[service_name] = {
                            "Before": before, "After": after,
                            "ExecutionTime": exec_time}
                else:
                    continue

            if package_name:
                service_data[package_name] = package_services
            else:
                print("Package name not found in JSON data.")

        return service_data

    def generate_flowchart(self) -> None:
        dot = graphviz.Digraph(
            comment='Service Execution Flowchart', format='png')
        dot.attr(rankdir='LR', nodesep='1', fontsize='11', splines='ortho')

        line_styles = {
            "before": {"style": "dashed", "color": "blue", "width": "2"},
            "after": {"style": "dotted", "color": "red", "width": "2"},
            "package": {"style": "solid", "color": "grey", "width": "2"}
        }

        dot.node("legend_header", label="Legend", shape='plaintext',
                 fontsize='16', fontcolor='black')
        dot.node("legend_before", label="Before", shape='rectangle',
                 style='filled', fillcolor=line_styles["before"]["color"])
        dot.node("legend_after", label="After", shape='rectangle',
                 style='filled', fillcolor=line_styles["after"]["color"])
        dot.node("legend_package", label="Package", shape='rectangle',
                 style='filled', fillcolor=line_styles["package"]["color"])

        dot.edge(
            "legend_header",
            "legend_before", label=" ",
            style=line_styles["before"]["style"],
            color=line_styles["before"]["color"])
        dot.edge(
            "legend_header",
            "legend_after", label=" ",
            style=line_styles["after"]["style"],
            color=line_styles["after"]["color"])
        dot.edge(
            "legend_header", "legend_package", label=" ",
            style=line_styles["package"]["style"],
            color=line_styles["package"]["color"])

        dot.node("System_Init", label="System Init", shape='rectangle',
                 style='filled', fillcolor='lightblue', rank='max')

        processed_nodes = set()

        for package_name, services in self.service_data.items():
            dot.node(
                package_name, label=package_name, shape='rectangle',
                style='filled', fillcolor=line_styles["package"]["color"],
                rank='same')

            dot.edge("System_Init", package_name,
                     style=line_styles["package"]["style"])

            for service_name, details in services.items():
                execution_time = details.get("ExecutionTime", "")
                service_label = f"""
                {service_name}\n({execution_time} ms)
                """ if execution_time else service_name
                dot.node(service_name, label=service_label,
                         shape='ellipse', style='filled', fillcolor='white')

                dot.edge(package_name, service_name)

                for before_service in details.get("Before", []):
                    if before_service in processed_nodes:
                        continue
                    dot.node(
                        before_service,
                        label=before_service, shape='ellipse',
                        style='filled', fillcolor='white', rank='same')
                    dot.edge(
                        before_service, service_name,
                        style=line_styles["before"]["style"],
                        color=line_styles["before"]["color"])
                    processed_nodes.add(before_service)

                for after_service in details.get("After", []):
                    if after_service in processed_nodes:
                        continue
                    dot.node(
                        after_service,
                        label=after_service,
                        shape='ellipse',
                        style='filled', fillcolor='white', rank='same')
                    dot.edge(
                        service_name, after_service,
                        style=line_styles["after"]["style"],
                        color=line_styles["after"]["color"])
                    processed_nodes.add(after_service)

                processed_nodes.add(service_name)

        try:
            dot.render('service_flowchart', cleanup=True)
            print("Flowchart generated as service_flowchart.png")
        except Exception as e:
            print(f"Error generating flowchart: {e}")


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

    def extract_package_version(self, package_name: str) -> str:
        try:
            with open(self.dpkg_status_path, 'r') as status_file:
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
            print(f"Error extracting package version for {package_name}: {e}")
            return None

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

    def extract_executable(self, name: str) -> List[str]:
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

    def check_info_files(self, exec_paths: List[str]) -> List[str]:
        info_files = []

        if os.path.exists(self.info_path):
            for file_name in os.listdir(self.info_path):
                if file_name.endswith(".list"):
                    list_file_path = os.path.join(
                        self.info_path, file_name)
                    with open(list_file_path, 'r') as list_file:
                        content = list_file.read()
                        for exec_path in exec_paths:
                            if os.path.islink(exec_path):
                                real_path = os.path.realpath(exec_path)
                            else:
                                real_path = os.path.abspath(exec_path)
                            if real_path in content:
                                info_files.append(
                                    os.path.splitext(file_name)[0])
                                break
        return info_files

    def service_analysis_process(self) -> None:
        entries = []

        for service_name, time in self.extracted_info.items():
            executable_paths = self.extract_executable(service_name)
            if not executable_paths:
                continue
            info_files = self.check_info_files(executable_paths)
            exec_names = [os.path.basename(path) for path in executable_paths]

            for package_name in info_files:
                version = self.extract_package_version(package_name)

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

        self.generate_table(combined_entries)

        if self.graphic_plot:
            try:
                TimeGraphPlot(
                    service_files_path=self.systemd_path,
                    json_data=self.out_data
                )
            except Exception as e:
                print(f"Error plotting graph: {e}")

    def generate_table(self, entries: List[chroot_mode_entry_service]) -> None:
        console = Console()
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

        console.print(table)
