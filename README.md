# Startup-SBOM

**What runs at boot, what it is made of, and how it can be attacked.**

Startup-SBOM statically analyses a Linux root filesystem, container or image and
answers three questions most SBOM tools can't:

1. **Vulnerability → threat.** Not "openssl has 14 CVEs", but *"an unauthenticated
   remote attacker who can reach TCP/22 could exploit CVE-2024-6387 in
   openssh-server (sshd, `ssh.service`, enabled at boot, runs as root) to execute
   code as root — EPSS 0.94, known exploited. Fix: upgrade to 1:9.2p1-2+deb12u3."*
   Every finding is placed in context: is it reachable at boot, through which service,
   linked by which binary, as which user, network-exposed, mitigated by which
   systemd hardening, mapped to MITRE ATT&CK, with a CISA SSVC decision
   (Track / Track\* / Attend / Act).
2. **Chained attacks.** A privilege-state attack graph
   (`remote → local:<user> → root → container escape → persistence`) built from
   vulnerabilities *and* misconfigurations (setuid/capability binaries, privileged
   containers, mounted Docker socket, kernel CVEs, writable units), pruned by
   hardening and ranked by likelihood × impact.
3. **Supply-chain blast radius.** A vendor → source package → binary package →
   file → service graph built from real code-loading edges (ELF `DT_NEEDED`,
   `.note.dlopen`, `ld.so.preload`, interpreters). It catches the
   xz → liblzma → libsystemd → sshd class of problem, which package dependencies
   alone miss. It also flags provenance risks: third-party repositories, unsigned or
   locally built packages, unmanaged binaries, modified files and EOL distributions.

It is **read-only by design**: nothing in the target is executed, mounted,
extracted or modified, and symlinks can never escape the analysed root.

## Install

```bash
uv tool install startup-sbom        # or: pipx install startup-sbom
uvx startup-sbom --help             # run without installing
docker run --rm ghcr.io/morpheuslord/startup-sbom --help
```

From source:

```bash
git clone https://github.com/morpheuslord/Startup-SBOM && cd Startup-SBOM
uv sync
uv run startup-sbom --help
```

Python ≥ 3.11 on Linux, macOS or Windows. Everything except `host:` mode and live
container acquisition is pure Python and host-OS independent.

## Usage

```bash
# A mounted disk or extracted rootfs
startup-sbom scan dir:/mnt/target_root -f html -f cyclonedx -o out/

# A running or stopped container (docker / podman / nerdctl)
startup-sbom scan docker:web -f json -f sarif

# Images without a container engine
startup-sbom scan docker-archive:./image.tar      # docker/podman save
startup-sbom scan oci-dir:./layout                 # OCI image layout
startup-sbom scan tar:./rootfs.tar.zst             # docker export / rootfs tarball

# The machine you are on (Linux)
sudo startup-sbom scan host: -f markdown

# CI gate: fail when anything warrants immediate action
startup-sbom scan oci-archive:img.tar -f sarif --fail-on act
```

| Option | Meaning |
|---|---|
| `-f, --format` | `json`, `cyclonedx`, `spdx`, `sarif`, `openvex`, `cdx-vex`, `markdown`, `html`, `dot`, `mermaid` (repeatable) |
| `-o, --output` | Output directory (default `./startup-sbom-out`), or `-` to stream one format to stdout |
| `--offline` | No network; use cached intelligence only |
| `--sources` | Vulnerability sources: `osv`, `arch`, `nvd` (opt-in, set `NVD_API_KEY`), or `none` |
| `--no-epss`, `--no-kev`, `--no-eol` | Skip exploit-prediction, known-exploited and end-of-life enrichment |
| `--no-language-packages` | Skip Python/npm/Go/Java/Rust inventory |
| `--no-link-analysis` | Skip ELF library reachability |
| `--integrity` | Verify installed files against package-database digests |
| `--boot-timing FILE` | `systemd-analyze plot` SVG or `blame` output captured on the target |
| `--platform` | Select a platform from a multi-arch image, e.g. `linux/arm64` |
| `--cdx-spec` | CycloneDX `1.5`, `1.6` (default) or `1.7` |
| `--fail-on` | `low` … `critical` (vulnerability severity) or `attend` / `act` (SSVC) |
| `-q`, `-v`, `--debug` | Quiet / verbose / debug |

Other commands: `startup-sbom db update|status|clear` (cache KEV/EPSS for offline
use), `startup-sbom schema` (JSON Schema of the native report), `startup-sbom version`.

Exit codes: `0` success, `1` `--fail-on` threshold reached, `2` usage or target
error, `3` internal error.

### Outputs

| Format | File | Use it for |
|---|---|---|
| `json` | `report.json` | Complete native report (versioned schema) |
| `cyclonedx` | `sbom.cdx.json` | Dependency-Track, Grype, Trivy; includes services, dependencies and vulnerabilities |
| `spdx` | `sbom.spdx.json` | SPDX 2.3 consumers |
| `sarif` | `results.sarif` | GitHub code scanning / CI annotations |
| `openvex`, `cdx-vex` | `vex.*.json` | Reachability-aware VEX for Grype, Trivy, Dependency-Track |
| `markdown` | `report.md` | Pull requests and wikis (Mermaid attack graphs render on GitHub) |
| `html` | `report.html` | Self-contained interactive report (works offline) |
| `dot`, `mermaid` | `attack-graph.*` | Attack graph for Graphviz / Mermaid |

VEX is conservative. A vulnerable package with no observed execution path is
reported as `under_investigation`, not `not_affected`, because "not started at
boot" is not the same as "unreachable". Opt in with `--vex-unreachable-not-affected`.

## Integrations

**GitHub Action**

```yaml
- uses: morpheuslord/Startup-SBOM@v2
  with:
    target: oci-archive:image.tar
    formats: sarif,cyclonedx
    fail-on: act
```

**pre-commit**

```yaml
- repo: https://github.com/morpheuslord/Startup-SBOM
  rev: v2.0.0
  hooks:
    - id: startup-sbom
      args: [scan, "dir:rootfs", --offline, --fail-on, act]
```

**Python**

```python
from startup_sbom import ScanOptions, scan

report = scan("docker-archive:image.tar", ScanOptions(offline=True))
for chain in report.attack_chains:
    print(chain.ssvc_decision, chain.narrative)
```

## Coverage

| Area | Supported |
|---|---|
| Package databases | dpkg (incl. distroless `status.d`), rpm (sqlite, Berkeley DB, NDB, without host rpm), apk, pacman |
| Distributions | Debian, Ubuntu, RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle, Amazon Linux, SUSE/openSUSE, Azure Linux, Alpine, Wolfi/Chainguard, Arch |
| Service managers | systemd (search paths, drop-ins, masks, templates, aliases, sockets, timers, boot graph, hardening exposure), SysV/LSB, OpenRC, runit, s6/s6-overlay, supervisord, BusyBox inittab, container entrypoints (tini/dumb-init/`sh -c` unwrapped) |
| Inputs | directories, live host, rootfs tarballs (gz/xz/bz2/zstd), docker/podman save archives, OCI layouts and archives, docker/podman/nerdctl containers and images |
| Vulnerability intelligence | OSV.dev (distro-aware, source-package matching), Arch security tracker, NVD (opt-in), FIRST EPSS, CISA KEV, endoflife.date |
| Language packages | Python, npm, Go (buildinfo), Java (Maven metadata), Rust (cargo-auditable) |

When a distribution is not covered by a vulnerability source, the report says so
explicitly under coverage limitations. It never returns a silent "0 vulnerabilities".

## Security model

* Never executes, mounts, chroots or uses `sudo`; never writes into the target.
* All target paths are resolved inside the analysed root, with a symlink budget.
  Non-regular files are refused and reads are size-capped.
* Archives are indexed in place, never extracted. Setuid bits and file capabilities
  are preserved for analysis.
* Network access is limited to an allow-list of HTTPS endpoints with TLS
  verification. `--offline` disables it entirely.
* Container environment variable values are never recorded.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Upgrading from 1.x

`python3 main.py …` still works through a compatibility shim that maps the old
flags. The old `chroot` mode has been removed: it bind-mounted the target over the
host's `/usr`, `/bin` and `/lib` and ran target binaries as root. Capture
`systemd-analyze plot > boot.svg` on the target and pass `--boot-timing boot.svg`
instead. See [Docs/Refactor Plan.md](Docs/Refactor%20Plan.md) for every change.

## Citation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19307312.svg)](https://doi.org/10.5281/zenodo.19307312)
See [CITATION.cff](CITATION.cff).

## License

MIT. Bundled MITRE CWE/CAPEC/ATT&CK-derived data and CTID mappings are
redistributed under their own terms; see `src/startup_sbom/data/NOTICE.md`.
