import re
from pydantic import BaseModel
from typing import Dict, List, Any


class OutputFormatInterface:
    def custom_output(self) -> Dict[str, Any]:
        raise NotImplementedError


class chroot_mode_entry_service(OutputFormatInterface, BaseModel):
    Package: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableNames: List[str]
    ExecutionTime: str
    Version: str
    Vulnerabilities: List[Dict[str, Any]] = []

    def custom_output(self) -> Dict[str, Any]:
        service_info = {
            "ServiceName": str(self.ServiceName),
            "ExecutablePath": str(self.ExecutablePath),
            "ExecutableNames": str(self.ExecutableNames),
            "ExecutionTime": str(self.ExecutionTime),
            "Version": str(self.Version)
        }
        if self.Vulnerabilities:
            service_info["Vulnerabilities"] = self.Vulnerabilities
        if self.Package:
            return {self.Package: service_info}
        return service_info

    def json(self, *args, **kwargs) -> Dict[str, Any]:
        return self.custom_output()

    @classmethod
    def combine_entries(
            cls,
            entries: List['chroot_mode_entry_service']
    ) -> List['chroot_mode_entry_service']:
        if not isinstance(entries, list):
            raise ValueError("Entries should be provided as a list")

        package_dict = {}
        for entry in entries:
            if not isinstance(entry, cls):
                raise ValueError("Invalid entry type provided")

            package_name = entry.Package
            if package_name:
                if package_name not in package_dict:
                    package_dict[package_name] = entry
                else:
                    existing_entry = package_dict[package_name]
                    existing_entry.ExecutablePath.extend(entry.ExecutablePath)
                    existing_entry.ExecutableNames.extend(
                        entry.ExecutableNames)
                    existing_entry.ExecutablePath.sort()
                    existing_entry.ExecutableNames.sort()
                    execution_time_str = str(entry.ExecutionTime)
                    try:
                        existing_entry.ExecutionTime = str(
                            re.search(r'\d+', execution_time_str).group())
                    except (AttributeError, ValueError):
                        # Keep original if regex fails
                        pass
                    if entry.Version > existing_entry.Version:
                        existing_entry.Version = entry.Version
                    
                    # Merge vulnerabilities if needed, or just keep one set
                    if entry.Vulnerabilities and not existing_entry.Vulnerabilities:
                        existing_entry.Vulnerabilities = entry.Vulnerabilities

        return list(package_dict.values())


class static_mode_entry_info(OutputFormatInterface, BaseModel):
    Package: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableName: List[str]
    Version: str
    Vulnerabilities: List[Dict[str, Any]] = []

    def custom_output(self) -> Dict[str, Any]:
        output = {
            "Package": self.Package,
            "ServiceInformation": {
                "ServiceName": self.ServiceName,
                "ExecutablePath": self.ExecutablePath,
                "ExecutableNames": self.ExecutableName,
                "Version": self.Version
            }
        }
        if self.Vulnerabilities:
            output["Vulnerabilities"] = self.Vulnerabilities
        return output

    def json(self, *args, **kwargs) -> Dict[str, Any]:
        return self.custom_output()


class static_mode_entry_service(OutputFormatInterface, BaseModel):
    Package: str = None
    Version: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableNames: List[str]
    Vulnerabilities: List[Dict[str, Any]] = []

    def custom_output(self) -> Dict[str, Any]:
        service_info = {
            "ServiceName": self.ServiceName,
            "ExecutablePath": self.ExecutablePath,
            "ExecutableNames": self.ExecutableNames
        }
        if self.Package:
            service_info["Package"] = self.Package
            service_info["Version"] = self.Version
        if self.Vulnerabilities:
            service_info["Vulnerabilities"] = self.Vulnerabilities
        return service_info

    def json(self, *args, **kwargs) -> Dict[str, Any]:
        return self.custom_output()

    @classmethod
    def combine_entries(
            cls,
            entries: List['static_mode_entry_service']
    ) -> List['static_mode_entry_service']:
        if not entries:
            raise ValueError("No entries provided")
        try:
            package_dict = {}
            for entry in entries:
                if not isinstance(entry, cls):
                    raise ValueError("Invalid entry type provided")
                package_name = entry.Package
                version = entry.Version
                if package_name:
                    if package_name not in package_dict:
                        package_dict[package_name] = entry
                    else:
                        existing_entry = package_dict[package_name]
                        existing_entry.ExecutablePath.extend(
                            entry.ExecutablePath)
                        existing_entry.ExecutableNames.extend(
                            entry.ExecutableNames)
                        existing_entry.ExecutablePath = sorted(
                            set(existing_entry.ExecutablePath))
                        existing_entry.ExecutableNames = sorted(
                            set(existing_entry.ExecutableNames))
                        if version and not existing_entry.Version:
                            existing_entry.Version = version
                        
                        if entry.Vulnerabilities and not existing_entry.Vulnerabilities:
                            existing_entry.Vulnerabilities = entry.Vulnerabilities
                            
            return list(package_dict.values())
        except Exception as e:
            print(f"Error combining entries: {e}")
            return []
