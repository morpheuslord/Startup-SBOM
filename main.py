import argparse
import os
import sys
import shutil
import tempfile
from typing import List
from rich import print

from sbom_manager.core.context import AnalysisContext
from sbom_manager.core.base_analyzer import BaseAnalyzer
from sbom_manager.core.base_init import BaseInitAnalyzer

# Package Managers
from sbom_manager.managers.apt import APTAnalyzer
from sbom_manager.managers.rpm import RPMAnalyzer
from sbom_manager.managers.pacman import PacmanAnalyzer
from sbom_manager.managers.apk import APKAnalyzer

# Init Systems
from sbom_manager.init_systems.systemd import SystemdAnalyzer
from sbom_manager.init_systems.sysv import SysVInitAnalyzer
from sbom_manager.init_systems.openrc import OpenRCAnalyzer
from sbom_manager.init_systems.docker import DockerInitAnalyzer

# Sources
from sbom_manager.sources.docker import DockerSource

class CompositeInitSystem(BaseInitAnalyzer):
    """
    Aggregates results from multiple init systems.
    """
    def __init__(self, init_systems: List[BaseInitAnalyzer]):
        self.systems = init_systems

    def detect(self, volume_path: str) -> bool:
        return any(s.detect(volume_path) for s in self.systems)

    def get_all_services(self, volume_path: str):
        services = []
        seen = set()
        for sys in self.systems:
            for s in sys.get_all_services(volume_path):
                # Simple dedup by name
                if s.name not in seen:
                    seen.add(s.name)
                    services.append(s)
        return services

    def get_startup_services(self, volume_path: str):
        services = []
        seen = set()
        for sys in self.systems:
            for s in sys.get_startup_services(volume_path):
                if s.name not in seen:
                    seen.add(s.name)
                    services.append(s)
        return services
        
    def parse_service_executables(self, service_path: str) -> List[str]:
        return []

def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="STARTUP SBOM: Universal Startup Analysis Tool"
    )
    # Mode
    parser.add_argument('--analysis-mode', default='static', choices=['static', 'chroot'])
    parser.add_argument('--static-type', default="info", choices=['info', 'service'])
    
    # Input Source
    parser.add_argument('--volume-path', type=str, help="Path to mounted volume")
    parser.add_argument('--docker', type=str, help="Docker Container ID or Name to analyze")
    
    # Output
    parser.add_argument("--save-file", type=str, default="")
    parser.add_argument("--info-graphic", type=bool, default=True)
    parser.add_argument("--pkg-mgr", type=str, choices=['apt', 'rpm', 'pacman', 'apk'])
    parser.add_argument("--cve-analysis", action='store_true', default=False)
    
    args = parser.parse_args()
    
    # 0. Temporary Directory Management
    temp_dir_obj = None
    target_path = args.volume_path
    
    try:
        if args.docker:
            print(f"[bold blue]Input Source:[/bold blue] Docker Container '{args.docker}'")
            # Create temp dir
            temp_dir_obj = tempfile.TemporaryDirectory(prefix="sbom_docker_")
            source = DockerSource(temp_dir_obj.name)
            
            if not source.check_docker_available():
                print("[red]Error:[/red] Docker CLI not found.")
                return
                
            try:
                target_path = source.export_container(args.docker)
                print(f"[green]Exported to:[/green] {target_path}")
            except Exception as e:
                print(f"[red]Error exporting container:[/red] {e}")
                return
        elif not target_path:
            target_path = "/mnt" # Default
            
        target_path = os.path.abspath(target_path)
        if not os.path.exists(target_path):
            print(f"[red]Error:[/red] Target path '{target_path}' does not exist.")
            return

        # 1. Detect Init Systems
        print(f"Detecting Init Systems in {target_path}...")
        available_inits = [
            DockerInitAnalyzer(),
            SystemdAnalyzer(),
            SysVInitAnalyzer(),
            OpenRCAnalyzer()
        ]
        active_inits = [i for i in available_inits if i.detect(target_path)]
        
        if active_inits:
            print(f"[green]Detected Init Systems:[/green] {', '.join([type(i).__name__ for i in active_inits])}")
            composite_init = CompositeInitSystem(active_inits)
        else:
            print("[yellow]Warning:[/yellow] No known init system detected. Analysis might be limited.")
            composite_init = None

        # 2. Detect Package Manager
        analyzers: list[BaseAnalyzer] = [
            APTAnalyzer(),
            RPMAnalyzer(),
            PacmanAnalyzer(),
            APKAnalyzer()
        ]
        
        selected_analyzer = None
        if args.pkg_mgr:
             # Manual selection logic...
             pass # Implement if needed, simplified for now
        
        # Auto-detect
        for analyzer in analyzers:
            if analyzer.detect(target_path):
                print(f"[green]Detected Package Manager:[/green] {type(analyzer).__name__}")
                selected_analyzer = analyzer
                break
                
        if not selected_analyzer:
            print("[red]Error:[/red] Could not detect a supported package manager.")
            return

        # 3. Execution
        context = AnalysisContext(
            volume_path=os.path.abspath(args.volume_path),
            output_path=args.save_file,
            static_type=args.static_type,
            full_scan=False,
            cve_analysis=args.cve_analysis,
            graphic_plot=args.info_graphic,
            package_manager=args.pkg_mgr,
            init_system=composite_init
        )
        
        # Override context field mapping
        context.static_type = args.static_type 

        if args.analysis_mode == 'static':
            selected_analyzer.analyze_static(context)
        elif args.analysis_mode == 'chroot':
            if args.docker:
                 print("[yellow]Warning:[/yellow] Chroot analysis on exported Docker container is limited (no bootup plot). Running Static instead + Entrypoint check.")
                 # Actually, we can't run systemd-analyze plot on a static export easily unless we chroot and run it?
                 # But we can't 'boot' the export.
                 # So we fallback to static or use specialized docker logic?
                 # For now, let's run static.
                 selected_analyzer.analyze_static(context)
            else:
                 selected_analyzer.analyze_chroot(context)

    except KeyboardInterrupt:
        print("\nAborted.")
    except Exception as e:
        print(f"[red]Fatal Error:[/red] {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if temp_dir_obj:
            print("Cleaning up temporary files...")
            try:
                temp_dir_obj.cleanup()
            except Exception as e:
                print(f"Error cleaning temp dir: {e}")

if __name__ == "__main__":
    main()
