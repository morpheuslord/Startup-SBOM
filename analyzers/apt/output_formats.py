import re
from pydantic import BaseModel
from typing import Dict, List, Any


class chroot_mode_entry_service(BaseModel):
    Package: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableNames: List[str]
    ExecutionTime: str

    def custom_output(self) -> Dict[str, Any]:
        service_info = {
            "ServiceName": str(self.ServiceName),
            "ExecutablePath": str(self.ExecutablePath),
            "ExecutableNames": str(self.ExecutableNames),
            "ExecutionTime": str(self.ExecutionTime)
        }
        if self.Package:
            return {self.Package: service_info}
        return service_info

    def json(self, *args, **kwargs) -> Dict[str, Any]:
        return self.custom_output()

    @classmethod
    def combine_entries(
            cls,
            entries: List[str]
    ) -> List[str]:
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
                    existing_entry.ExecutablePath.extend(
                        entry.ExecutablePath)
                    existing_entry.ExecutableNames.extend(
                        entry.ExecutableNames)
                    existing_entry.ExecutablePath.sort()
                    existing_entry.ExecutableNames.sort()
                    execution_time_str = str(entry.ExecutionTime)
                    try:
                        existing_entry.ExecutionTime = str(
                            re.search(r'\d+', execution_time_str).group())
                    except (AttributeError, ValueError):
                        raise ValueError("Invalid ExecutionTime format")

        return list(package_dict.values())


class static_mode_entry_info(BaseModel):
    Package: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableName: List[str]

    def custom_output(self) -> Dict[str, Any]:
        return {
            "Package": self.Package,
            "ServiceInformation": {
                f"{self.ServiceName}": {
                    "ExecutablePath": self.ExecutablePath,
                    "ExecutableName": self.ExecutableName
                }
            }
        }

    def json(self, *args, **kwargs) -> Dict[str, Any]:
        return self.custom_output()


class static_mode_entry_service(BaseModel):
    Package: str = None
    ServiceName: str
    ExecutablePath: List[str]
    ExecutableNames: List[str]

    def custom_output(self) -> Dict[str, Any]:
        service_info = {
            "ServiceName": self.ServiceName,
            "ExecutablePath": self.ExecutablePath,
            "ExecutableNames": self.ExecutableNames
        }
        if self.Package:
            return {self.Package: service_info}
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
            return cls.filter_duplicates_by_package(
                list(package_dict.values()))
        except Exception as e:
            print(f"Error combining entries: {e}")
            return []

    @classmethod
    def filter_duplicates_by_package(
        cls,
        entries: List['static_mode_entry_service']
    ) -> List['static_mode_entry_service']:
        unique_entries = {}
        for entry in entries:
            if not isinstance(entry, cls):
                raise ValueError("Invalid entry type provided")
            package_name = entry.Package
            if package_name not in unique_entries:
                unique_entries[package_name] = entry
            else:
                existing_entry = unique_entries[package_name]
                existing_entry.ExecutablePath.extend(
                    entry.ExecutablePath)
                existing_entry.ExecutableNames.extend(
                    entry.ExecutableNames)
                existing_entry.ExecutablePath = sorted(
                    set(existing_entry.ExecutablePath))
                existing_entry.ExecutableNames = sorted(
                    set(existing_entry.ExecutableNames))
        return list(unique_entries.values())
