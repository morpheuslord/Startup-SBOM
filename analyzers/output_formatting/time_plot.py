import os
import json
import graphviz
from typing import Dict, Any


class RpmTimeGraphPlot:
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
            output_path = dot.render('service_flowchart', cleanup=True, view=False)
            print(f"Flowchart generated: {output_path}")
        except graphviz.ExecutableNotFound:
            # Graphviz not installed - save DOT source and convert using alternative method
            dot.save('service_flowchart.dot')
            print("Warning: Graphviz executable not found. DOT file saved as service_flowchart.dot")
            print("Install Graphviz to generate PNG: sudo apt install graphviz")
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


class AptTimeGraphPlot:
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
            output_path = dot.render('service_flowchart', cleanup=True, view=False)
            print(f"Flowchart generated: {output_path}")
        except graphviz.ExecutableNotFound:
            # Graphviz not installed - save DOT source and convert using alternative method
            dot.save('service_flowchart.dot')
            print("Warning: Graphviz executable not found. DOT file saved as service_flowchart.dot")
            print("Install Graphviz to generate PNG: sudo apt install graphviz")
        except Exception as e:
            print(f"Error generating flowchart: {e}")
