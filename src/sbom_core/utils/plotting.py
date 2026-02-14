import os
import json
import logging
from typing import Dict, Any, List
from dataclasses import dataclass

try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    GRAPHVIZ_AVAILABLE = False

@dataclass
class ServiceNode:
    name: str
    execution_time: int
    before: List[str]
    after: List[str]
    package: str

class TimeGraphPlot:
    """
    Generates time execution flowcharts for services using Graphviz.
    """
    def __init__(self, service_files_path: str):
        self.service_files_path = service_files_path
        self.nodes: List[ServiceNode] = []

    def add_node(self, node: ServiceNode):
        self.nodes.append(node)

    def parse_service_file(self, service_name: str) -> Dict[str, List[str]]:
        """Parses a service file to find Before/After dependencies."""
        deps = {"Before": [], "After": []}
        service_file_path = os.path.join(self.service_files_path, service_name if service_name.endswith('.service') else f"{service_name}.service")
        
        if not os.path.exists(service_file_path):
            # Try without .service or with .service if not present
            return deps

        try:
            with open(service_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Before="):
                        deps["Before"].extend(line.split('=', 1)[1].split())
                    elif line.startswith("After="):
                        deps["After"].extend(line.split('=', 1)[1].split())
        except Exception as e:
            logging.error(f"Error reading service file {service_file_path}: {e}")
            
        return deps

    def plot_graph(self, output_name: str = 'service_flowchart'):
        if not GRAPHVIZ_AVAILABLE:
            print("Graphviz python library not available. Skipping plot.")
            return

        dot = graphviz.Digraph(comment='Service Execution Flowchart', format='png')
        dot.attr(rankdir='LR', nodesep='1', fontsize='11', splines='ortho')

        line_styles = {
            "before": {"style": "dashed", "color": "blue", "width": "2"},
            "after": {"style": "dotted", "color": "red", "width": "2"},
            "package": {"style": "solid", "color": "grey", "width": "2"}
        }

        # Legend
        dot.node("legend_header", label="Legend", shape='plaintext', fontsize='16', fontcolor='black')
        dot.node("legend_before", label="Before", shape='rectangle', style='filled', fillcolor=line_styles["before"]["color"])
        dot.node("legend_after", label="After", shape='rectangle', style='filled', fillcolor=line_styles["after"]["color"])
        dot.node("legend_package", label="Package", shape='rectangle', style='filled', fillcolor=line_styles["package"]["color"])
        
        # Legend edges (invisible to position)
        dot.edge("legend_header", "legend_before", style="invis")

        dot.node("System_Init", label="System Init", shape='rectangle',
                 style='filled', fillcolor='lightblue', rank='max')

        processed_nodes = set()
        
        # Group by package
        packages = {}
        for node in self.nodes:
            if node.package not in packages:
                packages[node.package] = []
            packages[node.package].append(node)

        for package_name, nodes in packages.items():
            package_id = f"pkg_{package_name}"
            dot.node(package_id, label=package_name, shape='rectangle',
                style='filled', fillcolor=line_styles["package"]["color"], rank='same')
            
            dot.edge("System_Init", package_id, style=line_styles["package"]["style"])

            for node in nodes:
                service_label = f"{node.name}\n({node.execution_time} ms)"
                dot.node(node.name, label=service_label, shape='ellipse', style='filled', fillcolor='white')
                dot.edge(package_id, node.name)

                # Dependencies
                # We re-parse dependencies here if they are not passed in node info?
                # The node info has them.
                for before in node.before:
                     if before not in processed_nodes: # avoiding dupes? Graphviz handles dupes fine
                         dot.node(before, label=before, shape='ellipse', style='filled', fillcolor='white')
                         dot.edge(before, node.name, label="Before", style=line_styles["before"]["style"], color=line_styles["before"]["color"])
                
                for after in node.after:
                    if after not in processed_nodes:
                        dot.node(after, label=after, shape='ellipse', style='filled', fillcolor='white')
                        dot.edge(node.name, after, label="After", style=line_styles["after"]["style"], color=line_styles["after"]["color"])
                
                processed_nodes.add(node.name)

        try:
            output_path = dot.render(output_name, cleanup=True, view=False)
            print(f"Flowchart generated: {output_path}")
        except graphviz.ExecutableNotFound:
            print("Graphviz executable not found. Install Graphviz to generate PNG.")
            dot.save(f'{output_name}.dot')
        except Exception as e:
            print(f"Error generating flowchart: {e}")
