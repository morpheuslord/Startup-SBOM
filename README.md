# Startup-SBOM

Startup-SBOM is a universal utility designed to provide an insider view of which packages are executed during the startup of a Linux system or within a Docker container.

By analyzing service files, init scripts, and container entrypoints, the tool maps every booting process to its originating package, providing a clear perspective on actual system execution.

## Features
- **Universal Init Support:** Automatically detects and analyzes Systemd, SysVinit, and OpenRC.
- **Docker Support:** Analyze running or stopped containers directly using `--docker`.
- **Multi-Package Manager Support:** Supports APT (Debian/Ubuntu), RPM (Fedora/CentOS/RHEL), Pacman (Arch), and APK (Alpine).
- **CVE Analysis:** Integrated vulnerability scanning using NVD data.
- **Graphical Output:** Generates service dependency flowcharts.
- **CycloneDX Export:** Generate industry-standard SBOMs.

## Installation
The packages needed are mentioned in the `requirements.txt` file and can be installed using pip:
```bash
pip3 install -r requirements.txt
```

## Usage

| Argument          | Description                                                                                                      |
|-------------------|-------------------|
| `--analysis-mode` | `static` or `chroot`. Default is `static`.                                                                       |
| `--static-type`   | `info` (Package DB) or `service` (Active Services). Default is `info`.                                           |
| `--volume-path`   | Path to a mounted filesystem. Default is `/mnt`.                                                                 |
| `--docker`        | Docker Container ID or Name to analyze.                                                                          |
| `--save-file`     | Path to save output (JSON/CycloneDX).                                                                            |
| `--info-graphic`  | Generate visual plots for CHROOT analysis. Default is `True`.                                                    |
| `--pkg-mgr`       | Explicitly specify package manager (apt, rpm, pacman, apk).                                                     |
| `--cve-analysis`  | Enable CVE vulnerability scanning.                                                                               |

### Usage Examples

#### 1. Analyze a Docker Container
```bash
python3 main.py --docker my-container --cve-analysis --save-file sbom.json
```

#### 2. Analyze a Mounted Volume (Static Service Mode)
```bash
python3 main.py --volume-path /mnt/target_root --static-type service --save-file output.json
```

#### 3. Chroot Analysis with Graphical Output
```bash
python3 main.py --analysis-mode chroot --volume-path /mnt/target_root --info-graphic True
```

## Supported Combinations

| OS Family | Package Manager | Init System |
|-----------|-----------------|-------------|
| Debian/Ubuntu | APT | Systemd, SysVinit |
| RHEL/CentOS | RPM | Systemd |
| Arch Linux | Pacman | Systemd |
| Alpine Linux | APK | OpenRC |
| Docker Containers | (Any) | Docker Entrypoint + Internal Init |

## Inner Workings
For detailed documentation on the methodology and process, please visit the [Wiki](https://github.com/morpheuslord/Startup-SBOM/wiki).

## TODO
- [x] Support for RPM
- [x] Support for APT
- [x] Support for Pacman
- [x] Support for APK (Alpine)
- [x] Support for Universal Init (Systemd, SysVinit, OpenRC)
- [x] Support for Docker Container Analysis
- [x] Support for CVE Analysis
- [x] Support for organized graphical output
- [x] Support for CycloneDX Export

## Ideas and Discussions
Ideas regarding this topic are welcome in the discussions page.
