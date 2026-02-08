from dataclasses import dataclass

@dataclass
class AnalysisContext:
    volume_path: str
    output_path: str
    static_mode: str = "static"
    static_type: str = "info"
    cve_analysis: bool = False
    graphic_plot: bool = False
    package_manager: str = ""
