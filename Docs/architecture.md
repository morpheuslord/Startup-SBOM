# Architecture

Startup-SBOM is a pipeline of isolated analysis stages that all read the target through one read-only virtual filesystem and all write into one versioned report model. This page describes the pipeline, the module map, the `Report` contract and the security posture that runs through every layer. Source references are to `src/startup_sbom/`.

## The pipeline

`startup_sbom.pipeline.scan()` is the single entry point for the CLI, the TUI and library use. It acquires the target, builds a `ScanContext` (the `RootFS`, the `ScanOptions`, warnings and coverage limitations) and runs the stages below. Each stage runs inside an isolation wrapper: a broken stage is logged, recorded as a warning plus a coverage limitation, and the scan continues (`strict=True`, used by `--debug`, makes failures raise instead). Progress and activity callbacks ([below](#activity-events-digests-and-raw-operations)) and a cooperative cancel event are supported.

1. **Identifying operating system** — `distro.identify()` reads the image's own `/etc/os-release` (never the host's) and maps it to OSV ecosystem strings (rolling Debian derivatives fall back to Debian testing, see [Vulnerabilities and Threats](vulnerabilities-and-threats.md#vulnerability-sources)).
2. **Reading package databases** — `pkgdb.read_all()` probes every supported database (an image can carry more than one) and feeds the file-ownership index.
3. **Discovering services** — `initsys.discover_all()` runs every init-system analyser whose `detect()` matches, reconciles them against PID 1, attaches optional boot timing (`--boot-timing`, or live data in `host:` mode) and attributes each service's executables to packages.
4. **Analysing executables and linked libraries** — `binaries` computes each service executable's transitive load closure (loader emulation), sweeps for setuid/capability and unmanaged executables, and — with link analysis on — computes the library closures of the setuid/capability binaries too, so threat reversal can tell which libraries a local user can make run as root.
5. **Confirming with the target's own tools (sandboxed)** (only with `--mode chroot` or `auto`) — `sandbox.open_sandbox()` checks the preconditions and self-tests a bubblewrap sandbox, then `sandbox.run_all()` runs the `systemd`, `loader` and `packages` probes; when the sandbox is unavailable the stage records why and the scan stays static. See [Chroot Mode](chroot-mode.md).
6. **Inventorying embedded language packages** (optional) — `langpkgs` adds Python, npm, Go, Java and Rust inventories.
7. **Matching vulnerabilities** (optional) — `vulns.match_vulnerabilities()` queries the enabled sources and enriches with EPSS and KEV.
8. **Checking end-of-life status** (optional) — `supplychain.eol` queries endoflife.date.
9. **Analysing supply chain** — `supplychain.analyze()` builds the vendor graph, provenance findings and blast radii.
10. **Reversing vulnerabilities into threats** — `threat.reverse_vulnerabilities()`, including each threat's triggers.
11. **Prefetching vulnerability intelligence** (optional, `--prefetch-intel`) — `intel.prefetch()`; threats are then re-reversed, because fresh intel (public PoC, active exploitation) may *raise* SSVC exploitation and risk but never lower them.
12. **Mapping chained attacks** — `threat.build_attack_chains()`.
13. **Explaining results** — `explain.explain_report()` fills evidence, derivations, exact score decompositions, SSVC traces and the global risk explanation.

A finalisation pass sorts every list canonically (so output is independent of analysis order) and computes the summary counters.

### Activity events, digests and raw operations

Besides `progress` (a `ProgressEvent(stage, index, total)` when each stage starts), `scan()` accepts an `activity` callback that receives `ActivityEvent(stage, kind, message, data)` objects while the scan runs:

* `op` — a **raw operation**. Stages log the concrete things they do (an HTTP request with its status, time and size; a cache hit; a package database read; an init system's service count; an ELF closure; a sandboxed command) to the dedicated `startup_sbom.ops` logger. While an activity sink is attached, `log.capture_ops()` forwards those records to it and stops them propagating, so they never interleave with a live display; otherwise they are ordinary log lines shown with `--verbose`.
* `digest` — after a stage finishes, a builder from `digest.py` summarises its in-memory results in one sentence plus the key numbers in `data`. Digests are built lazily (only when someone listens), bound every free-text value, and a failure to build one is logged, never raised.
* `stage-failed` — the stage raised and was isolated.

A failing sink never breaks the scan. The CLI dashboard, the `--journal` file, the TUI scan screen and the live analyst all consume these events; see [Live Scanning](live-scanning.md).

## Module map

| Module | Responsibility |
|---|---|
| `rootfs/` | Read-only, root-confined VFS: directory-backed and (layered) tar-backed implementations, file-capability decoding |
| `sources/` | Target parsing and acquisition: directories, the live host, tarballs, docker-archives, OCI layouts/archives, live engine containers and images; compression sniffing and the byte-budgeted workspace; hostile-input validation |
| `pkgdb/` | dpkg, rpm (sqlite/BDB/NDB), apk and alpm readers plus the path → owning-package index — see [Package Databases](package-databases.md) |
| `initsys/` | systemd, SysV, OpenRC, runit, s6, supervisord, inittab, container-entrypoint, cron and udev analysers — see [Init Systems](init-systems.md) |
| `binaries/` | Bounds-checked ELF reader, dynamic-loader emulation (glibc and musl search order), shebang parsing, privileged/unmanaged executable sweep |
| `sandbox/` | Chroot mode: the bubblewrap sandbox runner and the `systemd`, `loader` and `packages` probes — see [Chroot Mode](chroot-mode.md) |
| `langpkgs/` | Embedded language ecosystems: Python, npm, Go buildinfo, Java (Maven metadata), Rust (cargo-auditable) |
| `vulns/` | OSV, Arch tracker and opt-in NVD matching; EPSS/KEV enrichment; native version comparators — see [Vulnerabilities and Threats](vulnerabilities-and-threats.md) |
| `supplychain/` | Repository provenance, vendor attribution, integrity checking, EOL lookup, the vendor-chain graph and blast radii |
| `threat/` | Threat reversal (reachability, triggers, CVSS, CWE, ATT&CK, STRIDE, SSVC, scoring) and the R1–R12 attack-chain engine |
| `intel/` | Opt-in online intelligence prefetch with the SSRF-hardened `SafeFetcher` — see [Intelligence and AI](intelligence-and-ai.md) |
| `explain/` | Explainable-AI layer: provenance store, exact risk attribution, SSVC traces, counterfactual fix plans, global drivers |
| `viz/` | Deterministic visualisations: rich terminal renderables and dependency-free SVG charts |
| `ai/` | Agentic AI analysis over a finished report: providers, agents, grounding, MCP/A2A/ACP servers; the live analyst (`ai/live.py`) |
| `tui/` | Textual terminal UI (optional extra) |
| `report/` | Every output format — see [Outputs](outputs.md) |
| `dashboard.py`, `digest.py` | The CLI live dashboard and journal; one-sentence stage digests — see [Live Scanning](live-scanning.md) |
| `models.py` | The pydantic report model (the contract) |
| `net.py`, `textsafe.py`, `lz4frame.py` | Hardened HTTP, untrusted-text sanitisation, bounded LZ4 frame decoding |

## The Report model: one contract

`startup_sbom.models` defines the pydantic models that are the contract between every analysis stage and every output format. The schema is versioned through `SCHEMA_VERSION` (currently `"2.2"`) and published verbatim by `startup-sbom schema`. The top-level `Report` holds:

```text
metadata (tool, schema_version, scan_id, target, coverage)   os / container
summary          packages[]        services[]       binaries[]
vulnerabilities[]  threats[]       attack_chains[]  supply_chain
intel[]          evidence[]        derivations[]    explanations   ai   warnings[]
```

Models reject unknown fields (`extra="forbid"`), so a report either validates against the published schema or fails loudly. Every other format — CycloneDX, SPDX, SARIF, VEX, Markdown, HTML, PDF — renders from a canonicalised copy of this one model, which keeps severity, reachability and identifiers consistent across formats.

Coverage is part of the contract: `metadata.coverage` records which package databases, init systems and vulnerability sources were actually consulted, whether the scan ran offline, the analysis mode (`static` or `chroot`) with the sandboxed probes that ran, and every limitation encountered. Only sources genuinely consulted are listed (an enabled `arch` source on a Debian system is absent).

## Security posture

The target and everything fetched about it are treated as hostile input end to end.

* **Symlink-confined rootfs** (`rootfs/base.py`): all target access goes through `RootFS`; in-image paths are absolute POSIX strings, symlinks resolve inside the image root with a bounded hop budget, non-regular files are refused and reads are size-capped. The directory backend opens with `O_NOFOLLOW|O_NONBLOCK` and `fstat`-checks for regular files.
* **No extraction** (`rootfs/tar.py`, `sources/`): tar targets are indexed header-only, layers are flattened with OCI whiteout rules, and compressed data is decompressed once into a `tempfile.mkdtemp()` workspace where every byte written is charged against a budget, so decompression bombs fail fast. `tarfile.TarFile.extractall` is lint-banned project-wide.
* **Bounded decompressors**: gzip/xz/bzip2/zstd streams are capped, and `lz4frame.py` provides a pure-Python, strictly bounds-checked LZ4 *frame* decoder (used for Ubuntu's `.lz4` apt indexes) with an output cap, preferring the C extension when present.
* **Hostile-format parsers**: the ELF reader, the rpm header/BDB/NDB parsers, the OCI JSON readers and the boot-timing SVG reader all validate every offset, size, count and digest, cap input sizes, and parse attacker-controlled names only as keys into their own member maps.
* **SSRF-hardened networking** (`net.py`): HTTPS only, to an explicit host allow-list (path-prefix-restricted for shared hosts such as `raw.githubusercontent.com`); TLS verification is never disabled; timeouts and bounded retries everywhere; secret headers (`NVD_API_KEY`, `GITHUB_TOKEN`) are bound to single hosts and never logged; `--offline` means no socket is ever opened. Arbitrary advisory-reference URLs go through the even stricter `SafeFetcher` ([Intelligence and AI](intelligence-and-ai.md)).
* **Text sanitisation** (`textsafe.py`): every string from a scanned system, advisory or fetched article is stripped of terminal escape sequences, bidi overrides, zero-width characters and private-use code points before it reaches a terminal, the TUI, a document or an LLM — escaping markup alone is not enough, since `rich.text.Text` passes `ESC` straight through.
* **Subprocess discipline** (`sources/engine.py`): engine CLIs are located with `shutil.which`, called with argv lists only (no shell), `--` before every user operand, stdin `/dev/null`, timeouts and checked exit codes; container references are validated against strict grammars before any call, and container environment *values* are never recorded (only key names, with secret-looking keys flagged).
* **Sandboxed execution only in chroot mode** (`sandbox/runner.py`): in the default static mode nothing from the target is executed. With `--mode chroot`/`auto`, the target's loader, `systemctl` and package manager run only inside a bubblewrap sandbox — a new user namespace as `nobody` with all capabilities dropped, every namespace unshared (no network), the target root read-only, a cleared environment, resource limits, timeouts with process-group kill and streaming output caps — after a self-test proves the identity. Probe output is parsed as untrusted text. See [Chroot Mode](chroot-mode.md#limitations-and-residual-risk) for what this does not protect against.
