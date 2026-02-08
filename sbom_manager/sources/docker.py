import os
import json
import subprocess
import shutil
from typing import Optional, Dict, Any

class DockerSource:
    """
    Handles Docker container operations: export and metadata extraction.
    """
    
    def __init__(self, temp_dir: str):
        self.temp_dir = temp_dir

    def check_docker_available(self) -> bool:
        try:
            subprocess.run(["docker", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def export_container(self, container_id: str) -> str:
        """
        Exports the container filesystem to a temporary directory.
        Returns the path to the exported root.
        """
        export_path = os.path.join(self.temp_dir, container_id)
        if os.path.exists(export_path):
            shutil.rmtree(export_path)
        os.makedirs(export_path)

        # Gets metadata first to verify container existence and get Entrypoint
        meta = self.get_container_metadata(container_id)
        if not meta:
            raise ValueError(f"Container {container_id} not found or not running.")
            
        print(f"Exporting container {container_id} to {export_path}...")
        
        # Use docker export | tar
        # docker export outputs a tar stream
        
        tar_proc = subprocess.Popen(["docker", "export", container_id], stdout=subprocess.PIPE)
        subprocess.run(["tar", "-x", "-C", export_path], stdin=tar_proc.stdout, check=True)
        tar_proc.stdout.close()
        tar_proc.wait()
        
        # Write metadata to .docker_info.json in the root
        with open(os.path.join(export_path, ".docker_info.json"), "w") as f:
            json.dump(meta, f, indent=2)
            
        return export_path

    def get_container_metadata(self, container_id: str) -> Optional[Dict[str, Any]]:
        """
        Runs docker inspect to get Entrypoint, Cmd, Env, etc.
        """
        try:
            res = subprocess.run(
                ["docker", "inspect", container_id], 
                check=True, 
                stdout=subprocess.PIPE, 
                encoding='utf-8'
            )
            data = json.loads(res.stdout)
            if not data: return None
            
            info = data[0]
            config = info.get("Config", {})
            return {
                "Id": info.get("Id"),
                "Name": info.get("Name"),
                "Entrypoint": config.get("Entrypoint"),
                "Cmd": config.get("Cmd"),
                "WorkingDir": config.get("WorkingDir"),
                "Env": config.get("Env")
            }
        except Exception as e:
            print(f"Error inspecting container: {e}")
            return None
