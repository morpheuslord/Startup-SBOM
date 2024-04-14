import json
from typing import Dict, Set
from pydantic import BaseModel


class ServiceInfo(BaseModel):
    executable_paths: Set[str]


class PackageServiceInfo(BaseModel):
    package_version: str
    service_names: Dict[str, ServiceInfo]


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, 'dict'):
            return obj.dict()
        return super().default(obj)
