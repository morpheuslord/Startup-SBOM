<p align="center">
  <img src="https://raw.githubusercontent.com/morpheuslord/Startup-SBOM/main/Docs/assets/logo.svg" alt="Startup-SBOM logo" width="140">
</p>

<h1 align="center">Startup-SBOM</h1>

<p align="center"><strong>What runs at boot, what it is made of, and how it can be attacked.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/startup-sbom/"><img src="https://img.shields.io/pypi/v/startup-sbom" alt="PyPI version"></a>
  <a href="https://pypi.org/project/startup-sbom/"><img src="https://img.shields.io/pypi/pyversions/startup-sbom" alt="Python versions"></a>
  <a href="https://github.com/morpheuslord/Startup-SBOM/actions/workflows/ci.yml"><img src="https://github.com/morpheuslord/Startup-SBOM/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://morpheuslord.github.io/Startup-SBOM/"><img src="https://img.shields.io/badge/docs-GitHub%20Pages-06b6d4" alt="Documentation"></a>
  <a href="https://github.com/morpheuslord/Startup-SBOM/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/startup-sbom" alt="License: MIT"></a>
</p>

<p align="center"><a href="https://morpheuslord.github.io/Startup-SBOM/"><strong>Read the documentation →</strong></a></p>

Startup-SBOM statically analyses a Linux root filesystem, container or image and
answers three questions most SBOM tools can't:

1. **Vulnerability → threat.** Not "openssl has 14 CVEs", but *"an unauthenticated
   remote attacker who can reach TCP/22 could exploit CVE-2024-6387 in
   openssh-server (sshd, `ssh.service`, enabled at boot, runs as root) to execute
   code as root — EPSS 0.94, known exploited. Fix: upgrade to 1:9.2p1-2+deb12u3."*
   Every finding is placed in context: is it reachable at boot, through which service,
   linked by which binary, what triggers it (boot, socket, timer, cron, D-Bus, udev
   device event, setuid binary, kernel) and who can fire that trigger, as which user,
   network-exposed, mitigated by which
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

It is **read-only by design**: nothing in the target is mounted, extracted or
modified, symlinks can never escape the analysed root, and in the default static
mode nothing in the target is executed. The opt-in chroot mode (`--mode chroot`)
runs a few of the target's own tools to confirm the static results, only inside
an unprivileged, read-only, network-less bubblewrap sandbox.

## Install

```bash
uv tool install startup-sbom        # or: pipx install startup-sbom
uvx startup-sbom --help             # run without installing
docker run --rm ghcr.io/morpheuslord/startup-sbom --help
```

The core scanner has no heavy dependencies; optional features are extras:

| Extra | Adds |
|---|---|
| `startup-sbom[tui]` | Interactive terminal UI (`startup-sbom tui`) |
| `startup-sbom[pdf]` | PDF reports (`-f pdf`, Typst; PDF/A-3u + PDF/UA-1 by default) |
| `startup-sbom[ai]` | AI analysis across multiple LLM providers, DuckDuckGo search, MCP server |
| `startup-sbom[agents-server]` | A2A and ACP agent servers |
| `startup-sbom[all]` | Everything above |

```bash
uv tool install "startup-sbom[all]"
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

# Confirm with the target's own tools in a sandbox (needs bubblewrap), keep a journal
startup-sbom scan dir:/mnt/target_root --mode chroot --journal scan.jsonl -f html
```

| Option | Meaning |
|---|---|
| `-f, --format` | `json`, `cyclonedx`, `spdx`, `sarif`, `openvex`, `cdx-vex`, `markdown`, `html`, `dot`, `mermaid`, `pdf` (repeatable) |
| `-o, --output` | Output directory (default `./startup-sbom-out`), or `-` to stream one format to stdout |
| `--offline` | No network; use cached intelligence only |
| `--sources` | Vulnerability sources: `osv`, `arch`, `nvd` (opt-in, set `NVD_API_KEY`), or `none` |
| `--no-epss`, `--no-kev`, `--no-eol` | Skip exploit-prediction, known-exploited and end-of-life enrichment |
| `--no-language-packages` | Skip Python/npm/Go/Java/Rust inventory |
| `--no-link-analysis` | Skip ELF library reachability |
| `--integrity` | Verify installed files against package-database digests |
| `--boot-timing FILE` | `systemd-analyze plot` SVG or `blame` output captured on the target |
| `--mode` | `static` (default, reads files only), `chroot` (also run the target's loader, `systemctl` and package manager in a bubblewrap sandbox) or `auto` (chroot when possible) |
| `--no-derivative-fallback` | Don't match rolling Debian derivatives (Kali, …) against Debian testing advisories |
| `--no-cvss-impact-gate` | Let confidentiality-only (`I:N/A:N`) flaws count as code execution |
| `--platform` | Select a platform from a multi-arch image, e.g. `linux/arm64` |
| `--cdx-spec` | CycloneDX `1.5`, `1.6` (default) or `1.7` |
| `--fail-on` | `low` … `critical` (vulnerability severity) or `attend` / `act` (SSVC) |
| `--prefetch-intel` | Fetch advisories, exploit references and articles for the top findings (opt-in, online) |
| `--live` / `--no-live` | Live dashboard of stages, digests and raw operations on stderr (default: on a terminal) |
| `--journal FILE` | Write every stage, raw operation, digest and analyst note as JSON lines |
| `--ai-live` | An LLM comments on each stage while the scan runs (`ai` extra; display-only) |
| `--ai-provider`, `--ai-model`, `--ai-budget` | Live analyst provider, `provider:model-id`, and spending cap in USD (default `0.10`) |
| `-q`, `-v`, `--debug` | Quiet / verbose / debug |

Other commands: `startup-sbom tui` (interactive UI), `startup-sbom ai …` (AI analysis
and agent servers), `startup-sbom intel …` (CVE intelligence lookup),
`startup-sbom db update|status|clear` (cache KEV/EPSS for offline use),
`startup-sbom schema` (JSON Schema of the native report), `startup-sbom version`.

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
| `pdf` | `report.pdf` | Archival PDF with explanations and charts; the JSON report is attached inside |

VEX is conservative. A vulnerable package with no observed execution path is
reported as `under_investigation`, not `not_affected`, because "not started at
boot" is not the same as "unreachable". Opt in with `--vex-unreachable-not-affected`.

## Beyond the scanner

**Chroot mode.** `--mode chroot` asks the target's own dynamic loader, `systemctl`
and package manager to confirm what static analysis inferred: link closures,
unit enablement and the package inventory. They run as `nobody` in a bubblewrap
sandbox with no capabilities, no network, a read-only root, resource limits and
timeouts. Directory targets (`dir:`, `host:`) on a Linux host with unprivileged user
namespaces only; otherwise the scan stays static and says why.

**Live progress.** On a terminal, `scan` shows each stage as it runs with a
one-line digest of what it found and a rolling pane of raw operations (HTTP
requests, package databases read, ELF closures, sandboxed commands). `--journal`
records the same as JSON lines; `--ai-live` adds a cheap model's running
commentary, which is never written into the report.

**Explainable results.** Every risk score decomposes exactly into its factors
(baseline + contributions = total), every SSVC decision carries its decision path
and the flips that would change it, and the report proposes a minimal fix plan
that breaks every attack chain. The console, HTML, Markdown and PDF outputs render
these as charts and graphs.

**Interactive TUI.** `startup-sbom tui` walks through target selection, scan
settings, a live scan (stage digests, raw operations, optional live analyst) and an eight-tab results browser with search, filters,
explanations, intel articles and export.

**Intel prefetch.** `--prefetch-intel` gathers vendor advisories, exploit and PoC
references and readable articles for the highest-risk findings, over an
SSRF-hardened fetcher. Public exploitation evidence can raise a threat's priority,
never lower it.

**AI analysis.** `startup-sbom ai analyze report.json` runs grounded agents over a
report on your choice of LLM provider (Anthropic, OpenAI, Google, Groq, Mistral,
OpenRouter, Ollama) with `--provider`, `--model` or `--profile cheap|balanced|quality`,
optional DuckDuckGo search and a cost ceiling. Claims the report doesn't support
are flagged. The same analysis is available over MCP (Model Context Protocol) and as
A2A / ACP (Agent Communication Protocol) agent servers.

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
  rev: v2.0.4
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
| Service managers | systemd (search paths, drop-ins, masks, templates, aliases, sockets, timers, boot graph, hardening exposure), SysV/LSB, OpenRC, runit, s6/s6-overlay, supervisord, BusyBox inittab, container entrypoints (tini/dumb-init/`sh -c` unwrapped); cron jobs and udev rule programs, counted only when their daemon starts |
| Inputs | directories, live host, rootfs tarballs (gz/xz/bz2/zstd), docker/podman save archives, OCI layouts and archives, docker/podman/nerdctl containers and images |
| Vulnerability intelligence | OSV.dev (distro-aware, source-package matching; rolling Debian derivatives such as Kali against Debian testing, at reduced confidence), Arch security tracker, NVD (opt-in), FIRST EPSS, CISA KEV, endoflife.date |
| Language packages | Python, npm, Go (buildinfo), Java (Maven metadata), Rust (cargo-auditable) |

When a distribution is not covered by a vulnerability source, the report says so
explicitly under coverage limitations. It never returns a silent "0 vulnerabilities".

## Security model

* Never mounts, chroots or uses `sudo`; never writes into the target.
* In the default static mode, never executes anything from the target. With
  `--mode chroot`/`auto`, the target's loader, `systemctl` and package manager run
  only inside a bubblewrap sandbox: a new user namespace as `nobody`, all
  capabilities dropped, no network, the target root read-only, a cleared
  environment, resource limits, timeouts and output caps.
* All target paths are resolved inside the analysed root, with a symlink budget.
  Non-regular files are refused and reads are size-capped.
* Archives are indexed in place, never extracted. Setuid bits and file capabilities
  are preserved for analysis.
* Network access is limited to an allow-list of HTTPS endpoints with TLS
  verification. `--offline` disables it entirely.
* Container environment variable values are never recorded.

See [SECURITY.md](https://github.com/morpheuslord/Startup-SBOM/blob/main/SECURITY.md) for reporting vulnerabilities.

## Upgrading from 1.x

`python3 main.py …` still works through a compatibility shim that maps the old
flags. The old `chroot` mode has been removed: it bind-mounted the target over the
host's `/usr`, `/bin` and `/lib` and ran target binaries as root.
`--analysis-mode chroot` now maps to the sandboxed `--mode chroot`, which never
mounts over the host or runs anything as root. It does not produce boot timings:
capture `systemd-analyze plot > boot.svg` on the target and pass
`--boot-timing boot.svg`. See the [refactor plan](https://github.com/morpheuslord/Startup-SBOM/blob/main/Docs/Refactor%20Plan.md) for every change.

## Citation

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19307312.svg)](https://doi.org/10.5281/zenodo.19307312)
See [CITATION.cff](https://github.com/morpheuslord/Startup-SBOM/blob/main/CITATION.cff).

## License

MIT. Bundled MITRE CWE/CAPEC/ATT&CK-derived data and CTID mappings are
redistributed under their own terms; see [NOTICE.md](https://github.com/morpheuslord/Startup-SBOM/blob/main/src/startup_sbom/data/NOTICE.md).
