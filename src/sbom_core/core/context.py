from dataclasses import dataclass, field
from typing import Optional, Any

@dataclass
class AnalysisContext:
    volume_path: str
    output_path: Optional[str] = None
    graphic_plot: bool = False
    full_scan: bool = False
    static_type: str = "service" # 'info' or 'service'
    init_system: Any = None # Instance of BaseInitAnalyzer
    package_manager: str = ""
    cve_analysis: bool = False
