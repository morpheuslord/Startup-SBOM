# Startup-SBOM

Startup-SBOM is a distributed Software Bill of Materials (SBOM) scanning system designed to analyze packages and services on Linux systems and Docker containers. It now features a client-server architecture with a centralized dashboard and distributed agents.

## Features

- **Distributed Architecture**: Centralized server with multiple scanning agents.
- **Universal Init Support**: Automatically detects and analyzes Systemd, SysVinit, and OpenRC.
- **Docker Support**: Analyze running or stopped containers directly using `--docker`.
- **Multi-Package Manager Support**: Supports APT (Debian/Ubuntu), RPM (Fedora/CentOS/RHEL), Pacman (Arch), and APK (Alpine).
- **CVE Analysis**: Integrated vulnerability scanning using NVD data.
- **Web Dashboard**: Real-time view of agents, scans, packages, and vulnerabilities.
- **CycloneDX Export**: Generate industry-standard SBOMs.

## Project Structure

- `src/sbom_server`: FastAPI-based central server and dashboard.
- `src/sbom_agent`: Agent service that runs scans and reports to the server.
- `src/sbom_cli`: Command-line interface for standalone operations.
- `src/sbom_core`: Shared logic, configuration, and models.
- `config/`: Configuration files (`sbom.conf`, `sbom.yaml`).

## Getting Started

### 1. Using Docker (Recommended)

The easiest way to run the full system is using Docker Compose.

```bash
docker-compose up --build
```

- **Server Dashboard**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

### 2. Manual Installation (Development)

Prerequisites: Python 3.11+, Poetry

1. **Install Dependencies**:
   ```bash
   poetry install
   ```

2. **Run Server**:
   ```bash
   poetry run sbom-server
   ```

3. **Run Agent**:
   ```bash
   # In a separate terminal
   poetry run sbom-agent
   ```

4. **Run CLI Tool** (Legacy/Standalone Mode):
   ```bash
   poetry run sbom-cli --help
   ```

## Configuration

Configuration is managed via `config/sbom.conf` or environment variables.

### Example `config/sbom.conf`
```yaml
server:
  host: "0.0.0.0"
  port: 8000
  db_path: "data/sbom.db"

agent:
  id: "agent-01"
  server_url: "http://localhost:8000"
  poll_interval: 30
  scanners:
    - "apt"
    - "docker"
```

### Environment Variables
- `SBOM_CONFIG`: Path to config file.
- `SBOM_HOST`: Server host (default: 0.0.0.0).
- `SBOM_PORT`: Server port (default: 8000).

## Inner Workings
For detailed documentation on the methodology and process, please visit the [Wiki](https://github.com/morpheuslord/Startup-SBOM/wiki).

## License
MIT License
