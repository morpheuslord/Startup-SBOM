import os
import re
import rpm
import json
import subprocess
import graphviz
from typing import Dict, List, Any, Union
from rich.console import Console
from rich.table import Table


class TimeGraphPlot:
    def __init__(self, service_files_path: str, json_data: str) -> None:
        self.service_files_path: str = service_files_path
        self.json_data: str = json_data
        self.service_data: Dict[str, Any] = {}
        self.render_process_run()

    def parse_service_files(self) -> Dict[str, Any]:
        result = {}

        try:
            data_dict = json.loads(self.json_data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON data: {e}")
            return result

        for package_name, package_info in data_dict.items():
            service_files = package_info.get("ServiceFiles", [])

            if not service_files:
                print(f"No service files found for {package_name}")
                continue

            package_services = {}

            for service_info in service_files:
                service_name = service_info.get("ServiceName")
                execution_time = service_info.get("ExecutionTime")

                if not service_name or not execution_time:
                    print(f"Skipping invalid service entry for {package_name}")
                    continue

                exec_time = str(execution_time)
                if "ms" in exec_time:
                    exec_time = int(''.join(filter(str.isdigit, exec_time)))

                service_file_path = os.path.join(
                    self.service_files_path, service_name)

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
                            "Before": before,
                            "After": after,
                            "ExecutionTime": exec_time
                        }
                else:
                    print(f"Service file not found for {service_name}")

            if package_name:
                result[package_name] = package_services

        return result

    def plot_graph(self) -> None:
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
            "legend_header", "legend_before", label=" ",
            style=line_styles["before"]["style"],
            color=line_styles["before"]["color"])
        dot.edge(
            "legend_header", "legend_after", label=" ",
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
                style='filled',
                fillcolor=line_styles["package"]["color"], rank='same')

            dot.edge("System_Init", package_name,
                     style=line_styles["package"]["style"])

            for service_name, details in services.items():
                execution_time = details.get("ExecutionTime", "")
                service_label = f"""
                {service_name}\n({execution_time} ms)
                """ if execution_time else service_name
                dot.node(service_name, label=service_label, shape='ellipse',
                         style='filled', fillcolor='white', rank='same')

                dot.edge(package_name, service_name)

                for before_service in details.get("Before", []):
                    if before_service in processed_nodes:
                        continue
                    dot.node(before_service, label=before_service,
                             shape='ellipse',
                             style='filled', fillcolor='white', rank='same')
                    dot.edge(before_service, service_name, label="Before",
                             style=line_styles["before"]["style"],
                             color=line_styles["before"]["color"])
                    processed_nodes.add(before_service)

                for after_service in details.get("After", []):
                    if after_service in processed_nodes:
                        continue
                    dot.node(after_service, label=after_service,
                             shape='ellipse',
                             style='filled', fillcolor='white', rank='same')
                    dot.edge(service_name, after_service, label="After",
                             style=line_styles["after"]["style"],
                             color=line_styles["after"]["color"])
                    processed_nodes.add(after_service)

                processed_nodes.add(service_name)

        try:
            dot.render('service_flowchart', cleanup=True)
            print("Flowchart generated as service_flowchart.png")
        except Exception as e:
            print(f"Error generating flowchart: {e}")

    def render_process_run(self) -> None:
        self.service_data = self.parse_service_files()

        if not self.service_data:
            print("No valid service data found.")
            return

        try:
            with open('Service_mapping.json', 'w+') as file:
                json.dump(self.service_data, file)
        except Exception as e:
            print(f"Error writing to file: {e}")

        self.plot_graph()


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

    def find_unique_service_files(self) -> List[str]:
        service_files = []
        try:
            for filename in os.listdir(self.systemd_path):
                if filename.endswith('.service'):
                    service_files.append(os.path.join(
                        self.systemd_path, filename))
        except OSError as e:
            print(e)
        return service_files

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

    def rpm_chroot_process(self) -> None:
        self.run_bootup_analysis()
        self.extract_service_times()
        self.create_packages_json()

        organized_data = {}

        for service_name, time in self.extracted_info.items():
            executable_paths = self.extract_executable(service_name)
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
        if self.output_opt:
            try:
                with open(self.output_opt, 'w+') as out:
                    out.write(self.organized_data)
            except Exception as e:
                print(f"Error writing to output file: {e}")
        self.display_service_info()
        if self.graphic_plot is True:
            TimeGraphPlot(
                service_files_path=self.systemd_path,
                json_data=self.organized_data
            )
        else:
            pass

    def display_service_info(self) -> None:
        data = json.loads(self.organized_data)

        console = Console()
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

        console.print(table)


if __name__ == "__main__":
    rpm_chroot_analysis(
        volume_path="/",
        output_opt="test.json",
        graphic_plot=True
    )
