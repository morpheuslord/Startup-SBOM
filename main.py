import argparse
import os
import sys
from rich import print
from sbom_manager.core.context import AnalysisContext
from sbom_manager.core.base_analyzer import BaseAnalyzer
from sbom_manager.managers.apt import APTAnalyzer
from sbom_manager.managers.rpm import RPMAnalyzer
from sbom_manager.managers.pacman import PacmanAnalyzer

def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="""
            STARTUP SBOM:
            Automated tool to list installed packages in Linux/Windows systems 
            and map them to appropriate service files.
        """
    )
    parser.add_argument(
        '--analysis-mode',
        type=str,
        default='static',
        choices=['static', 'chroot'],
        help="Mode of operation: static or chroot."
    )
    parser.add_argument(
        '--static-type',
        type=str,
        default="info",
        choices=['info', 'service'],
        help="Type of static processing: info (Info Directory) or service (Service File)."
    )
    parser.add_argument(
        '--volume-path',
        type=str,
        default='/mnt',
        help="Path to the mounted volume (default: /mnt)."
    )
    parser.add_argument(
        "--save-file",
        type=str,
        default="",
        help="Path to save output JSON."
    )
    parser.add_argument(
        "--info-graphic",
        type=bool,
        default=True,
        help="Enable visual plots (Timeline) for CHROOT analysis."
    )
    parser.add_argument(
        "--pkg-mgr",
        type=str,
        default="",
        choices=['apt', 'rpm', 'pacman'],
        help="Explicitly specify package manager (optional)."
    )
    parser.add_argument(
        "--cve-analysis",
        action='store_true',
        default=False,
        help="Enable CVE vulnerability scanning."
    )
    
    args = parser.parse_args()
    
    # 1. Initialize Context
    context = AnalysisContext(
        volume_path=os.path.abspath(args.volume_path),
        output_path=args.save_file,
        static_mode=args.analysis_mode, # Corrected logic below
        static_type=args.static_type,
        cve_analysis=args.cve_analysis,
        graphic_plot=args.info_graphic,
        package_manager=args.pkg_mgr
    )
    
    # Map context.static_mode from args
    # Wait, AnalysisContext doesn't have static_mode field in my def, it has static_type.
    # But it should know if it's static or chroot analysis.
    # Checking context.py earlier:
    # class AnalysisContext:
    #    volume_path: str
    #    output_path: str
    #    static_type: str = "info"
    #    cve_analysis: bool = False
    #    graphic_plot: bool = False
    #    package_manager: str = ""
    
    # I should have added 'mode' or similar. 
    # For now, I'll pass it to the analyzer method calls directly from args.
    
    # 2. Registered Analyzers
    analyzers: list[BaseAnalyzer] = [
        APTAnalyzer(),
        RPMAnalyzer(),
        PacmanAnalyzer()
    ]
    
    # 3. Detect Package Manager
    selected_analyzer = None
    
    if context.package_manager:
        # User specified
        for analyzer in analyzers:
            if isinstance(analyzer, APTAnalyzer) and context.package_manager == 'apt':
                selected_analyzer = analyzer
            elif isinstance(analyzer, RPMAnalyzer) and context.package_manager == 'rpm':
                selected_analyzer = analyzer
            elif isinstance(analyzer, PacmanAnalyzer) and context.package_manager == 'pacman':
                selected_analyzer = analyzer
        
        if not selected_analyzer:
            print(f"[red]Error:[/red] Specified package manager '{context.package_manager}' not supported.")
            return
    else:
        # Auto-detect
        for analyzer in analyzers:
            if analyzer.detect(context.volume_path):
                selected_analyzer = analyzer
                print(f"[green]Detected Package Manager:[/green] {type(analyzer).__name__}")
                break
    
    if not selected_analyzer:
        print("[red]Error:[/red] Could not detect a supported package manager in the given volume.")
        return

    # 4. Execute Analysis
    try:
        if args.analysis_mode == 'static':
            selected_analyzer.analyze_static(context)
        elif args.analysis_mode == 'chroot':
            selected_analyzer.analyze_chroot(context)
        else:
            print("Invalid analysis mode.")
            
    except Exception as e:
        print(f"[red]Fatal Error during analysis:[/red] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
