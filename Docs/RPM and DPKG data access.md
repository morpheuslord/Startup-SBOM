## Database Accessing

For the SBOM (Software Bill of Materials) tool, database access is crucial for extracting and analyzing package-related data without the need for direct access to the underlying system image.

## Table of Contents
- [Need to access the DB](#need-to-access-the-db)
- [Methods to access the DB](#methods-to-access-the-db)
    - [APT Data Accessing](#apt-data-accessing)
    - [RPM Data Accessing](#rpm-data-accessing)

---

## Need to access the DB

The database access is necessary to retrieve information about packages and associated files from the system's package managers (APT and RPM). This approach avoids the risks associated with direct access to the system image.

---

### Methods to access the DB

### APT Data Accessing

**Listing Information Files**

The `list_info_files` method retrieves a list of files with a `.list` extension from a specified directory (`self.info_path`). This is useful for gathering metadata related to APT packages.

```python
def list_info_files(self) -> list[str]:
    try:
        files_with_list_extension = []
        for filename in os.listdir(self.info_path):
            if filename.endswith(".list"):
                files_with_list_extension.append(os.path.join(filename))
        return files_with_list_extension
    except Exception as e:
        print(f"Error listing info files: {e}")
        return []
```

**Listing Service Files**

The `list_service_files` method takes a `list_name` parameter (representing a specific file) and retrieves service-related file paths based on regex matching within the file. This is particularly useful for identifying service-related configurations.

```python
def list_service_files(self, list_name: str) -> List[str]:
    try:
        file_paths = []
        list_file_path = os.path.join(self.info_path, list_name)
        if os.path.exists(list_file_path):
            with open(list_file_path, 'r') as file:
                for line in file:
                    if re.search(r'\.service\b(?![.\w])', line):
                        file_paths.append(line.strip())
        return file_paths
    except Exception as e:
        print(f"Error listing service files: {e}")
        return []
```

**Listing Executable Paths**

The `list_executable_paths` method extracts executable paths from a specified `service_path`, resolving any symbolic links to obtain the actual paths. This is essential for understanding the executables associated with services.

```python
def list_executable_paths(self, service_path: str) -> List[str]:
    try:
        service_path_mounted = f"{self.volume_path}/{service_path}"
        executable_paths = []
        if os.path.exists(service_path_mounted):
            with open(service_path_mounted, 'r') as file:
                for line in file:
                    match = re.search(r'Exec(?:Start|Stop|Pre)?=(\S+)', line)
                    if match:
                        executable_path = match.group(1)
                        if os.path.islink(executable_path):
                            real_path = os.path.realpath(executable_path)
                        else:
                            real_path = os.path.abspath(executable_path)
                        executable_paths.append(real_path)
        return executable_paths
    except Exception as e:
        print(f"Error listing executable paths: {e}")
        return []
```

### RPM Data Accessing

**Setting RPM Database Path**

The `set_rpm_db_path` method sets the path for the RPM database (`rpm_db_path`) within the system volume. This ensures that RPM operations can correctly access the package database.

```python
def set_rpm_db_path(self) -> None:
    rpm_db_path = os.path.join(self.volume_path, 'var', 'lib', 'rpm')
    rpm.addMacro("_dbpath", rpm_db_path)
```

**Creating Packages JSON**

The `create_packages_json` method extracts package information from the RPM database. It retrieves package names, versions, and associated service files along with their executable paths.

```python
def create_packages_json(self) -> Dict[str, PackageServiceInfo]:
    package_info = {}
    ts = rpm.TransactionSet()
    mi = ts.dbMatch()

    for hdr in mi:
        package_name = hdr[rpm.RPMTAG_NAME].decode('utf-8')
        package_version = hdr[rpm.RPMTAG_VERSION].decode('utf-8')
        files = hdr[rpm.RPMTAG_FILENAMES]

        if files:
            service_files = [
                f.decode('utf-8') for f in files if f.decode('utf-8').endswith('.service')
            ]

            if service_files:
                # Use set to ensure uniqueness
                service_info = ServiceInfo(executable_paths=set())
                for service_file in service_files:
                    executable_paths = self.extract_executable_paths(
                        os.path.join(self.systemd_path, service_file))
                    if executable_paths:
                        service_info.executable_paths.update(executable_paths)

                if package_name not in package_info:
                    package_info[package_name] = PackageServiceInfo(
                        package_version=package_version, service_names={})
                package_info[package_name].service_names[service_file] = service_info

    return package_info
```

In summary, these methods provide efficient and secure access to package-related data from APT and RPM systems, enabling the SBOM tool to gather essential information for software analysis and management without compromising system integrity.