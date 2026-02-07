# CVE Analysis

The Startup-SBOM tool includes a built-in vulnerability scanner that checks installed packages against the National Vulnerability Database (NVD) to identify known Common Vulnerabilities and Exposures (CVEs).

## Overview

The CVE Analysis feature uses the [nvdlib](https://github.com/Vehemont/nvdlib) library to query the NIST NVD API v2. It correlates package names and versions found on your system (via APT or RPM) with known vulnerabilities.

## Usage

To enable CVE analysis, add the `--cve-analysis` flag to your command:

```bash
python3 main.py --pkg-mgr apt --analysis-mode static --static-type service --volume-path / --cve-analysis
```

This flag works with both **static** and **chroot** analysis modes.

## output

When enabled, the output table will include a **CVEs** column:

| Package | Version | Service Name | ... | CVEs |
|---------|---------|--------------|-----|------|
| openssh-server | 8.2p1 | ssh.service | ... | [red bold]1 CRIT[/red bold]<br>[red]2 HIGH[/red] |

- **CRITICAL**: CVSS v3.1 score 9.0 - 10.0
- **HIGH**: CVSS v3.1 score 7.0 - 8.9
- **MEDIUM**: CVSS v3.1 score 4.0 - 6.9
- **LOW**: CVSS v3.1 score 0.1 - 3.9

The JSON output will also include a `Vulnerabilities` list for each package containing detailed CVE data (ID, score, severity).

## Configuration

### API Key (Recommended)

The NVD API has rate limits:
- **Without API Key**: 6 seconds delay between requests
- **With API Key**: 0.6 seconds delay between requests

For faster analysis, especially when scanning many packages, it is highly recommended to obtain a free API key from [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key) and set it as an environment variable:

**Linux/Mac:**
```bash
export NVD_API_KEY="your-api-key-here"
```

**Windows (PowerShell):**
```powershell
$env:NVD_API_KEY="your-api-key-here"
```

The tool will automatically detect this environment variable and adjust the rate limiting speed.

## Troubleshooting

- **No CVEs found**: Ensure you have internet connectivity. Some packages may have different naming conventions in NVD versus your package manager.
- **Slow analysis**: This is expected without an API key due to rate limiting. Get an API key to speed it up significantly.
- **nvdlib error**: Ensure dependencies are installed: `pip install -r requirements.txt`.
